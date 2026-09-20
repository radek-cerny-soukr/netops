from __future__ import annotations

import base64
import hashlib
import os

from . import ssh as ssh_module

PREFIX = "SHA256:"
DIGEST_LENGTH = 43
KEYSCAN_BINARY = "ssh-keyscan"
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


def keyscan_argv(host, port, timeout_seconds) -> list:
    name = _checked_host(host)
    number = _checked_port(port)
    seconds = _checked_timeout(timeout_seconds)
    return [KEYSCAN_BINARY, "-T", str(max(1, int(seconds))), "-p", str(number), name]


def matching_line(lines, pin) -> str:
    fingerprint = checked_pin(pin)
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
            return line
        offered += 1
    raise HostKeyError(
        "no offered host key matches the pinned fingerprint %s, %d key(s) offered"
        % (fingerprint, offered)
    )


def _env() -> dict:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}


def scan(
    host, port, pin, timeout_seconds, *, capture_max_bytes=KEYSCAN_CAPTURE_MAX_BYTES, run=None
) -> str:
    fingerprint = checked_pin(pin)
    argv = keyscan_argv(host, port, timeout_seconds)
    seconds = _checked_timeout(timeout_seconds)
    try:
        budget = ssh_module._checked_capture(capture_max_bytes)
        runner = run if run is not None else ssh_module._capped_runner(budget)
        result = runner(argv, capture_output=True, timeout=seconds, check=False, env=_env())
    except ssh_module.SshError as error:
        raise HostKeyError(
            "cannot read the host key of %s: %s" % (argv[-1], error)
        ) from None
    except Exception as error:
        raise HostKeyError(
            "cannot read the host key of %s (%s)" % (argv[-1], type(error).__name__)
        ) from None
    output = getattr(result, "stdout", None)
    if not isinstance(output, (bytes, bytearray)):
        raise HostKeyError(
            "the host key scan must answer with bytes on stdout, got %s" % type(output).__name__
        )
    data = bytes(output)
    code = getattr(result, "returncode", None)
    if code != 0 or not data:
        raise HostKeyError("%s offered no host key, exit code %s" % (argv[-1], code))
    return matching_line(data.decode("utf-8", "replace").splitlines(), fingerprint)


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
