from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone

from . import hostkey, legacy_ssh as legacy_module

SSH_BINARY = "ssh"
CONFIG_FILE = "/dev/null"
DEFAULT_TIMEOUT_SECONDS = 120.0
MOMENT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
WORKSPACE_PREFIX = "netops-core-"
IDENTITY_NAME = "identity"
SECRET_NAME = "secret"
ASKPASS_NAME = "askpass"
ASKPASS_SCRIPT = '#!/bin/sh\ncat "$NETOPS_ASKPASS_FILE"\n'
KIND_PASSWORD = "password"
KIND_KEY = "ssh-key"
AUTH_KINDS = (KIND_PASSWORD, KIND_KEY)
SAID_CHARS = 200
NEGOTIATION_MARKER = "no matching"
CLIENT_FAILURE_CODE = 255
OPTIONS = (
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "IdentitiesOnly=yes",
    "ClearAllForwardings=yes",
    "ProxyCommand=none",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "ControlPath=none",
)
PASSWORD_OPTIONS = ("BatchMode=no",) + OPTIONS[1:] + (
    "NumberOfPasswordPrompts=1",
    "PubkeyAuthentication=no",
)
LEGACY_REMEDY = (
    "; %s offers only algorithms this client refuses - if that is intended for this one device,"
    " name the exception in its inventory entry as legacy_ssh, one of the profiles %s;"
    " there is no global switch and no other entry is weakened by it"
)


class SshError(Exception):
    def __init__(self, message, rc=None, said=""):
        super().__init__(message)
        self.rc = rc
        self.said = said


@dataclass(frozen=True)
class Result:
    rc: int
    stdout: bytes
    said: str
    started_at: str
    finished_at: str


def _checked_text(name, value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SshError("%s must be a non-empty string, got %r" % (name, value))
    return value


def _checked_host(value) -> str:
    host = _checked_text("host", value).strip()
    if (
        "@" in host
        or "://" in host
        or host.startswith("-")
        or any(mark in host for mark in ("/", "?", "#", " ", "\t"))
    ):
        raise SshError(
            "host must be a bare host name or address, the login is a separate argument, got %r"
            % (value,)
        )
    return host


def _checked_port(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise SshError("port must be a whole number between 1 and 65535, got %r" % (value,))
    return value


def _checked_login(value) -> str:
    login = _checked_text("login", value).strip()
    if login.startswith("-") or any(mark in login for mark in ("@", ":", "/", " ", "\t")):
        raise SshError(
            "login must be a plain user name without @, : or whitespace, got %r" % (value,)
        )
    return login


def _checked_command(value) -> str:
    command = _checked_text("command", value)
    if any(mark in command for mark in ("\n", "\r", "\x00")):
        raise SshError("command must be a single line, got %r" % (value,))
    return command


def _checked_timeout(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SshError("timeout must be a positive number of seconds, got %r" % (value,))
    seconds = float(value)
    if not 0 < seconds < float("inf"):
        raise SshError("timeout must be a positive number of seconds, got %r" % (value,))
    return seconds


def _checked_credential(value):
    kind = getattr(value, "kind", None)
    if isinstance(value, (str, bytes, bytearray)) or not callable(getattr(value, "use", None)):
        raise SshError(
            "credential must be a credential store record with use(), got %s"
            % type(value).__name__
        )
    if kind not in AUTH_KINDS:
        raise SshError(
            "ssh authenticates with a credential of kind %s, got %r"
            % (" or ".join(AUTH_KINDS), kind)
        )
    return kind


def _clock(now):
    if now is None:
        return lambda: datetime.now(timezone.utc)
    if callable(now):
        return now
    raise SshError("now must be a callable returning an aware datetime, got %r" % (now,))


def _moment(clock) -> str:
    value = clock()
    if not isinstance(value, datetime):
        raise SshError("clock must return a datetime, got %r" % (value,))
    if value.tzinfo is None or value.utcoffset() is None:
        raise SshError("clock must return a timezone aware datetime, got %r" % (value,))
    return value.astimezone(timezone.utc).strftime(MOMENT_FORMAT)


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
    if len(text) > SAID_CHARS:
        text = text[:SAID_CHARS] + "..."
    return text


def _secret_bytes(name, secret) -> bytes:
    if isinstance(secret, str):
        data = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        data = bytes(secret)
    else:
        raise SshError(
            "credential must hand over the %s as text, got %s" % (name, type(secret).__name__)
        )
    if not data:
        raise SshError("credential handed over an empty %s" % name)
    return data if data.endswith(b"\n") else data + b"\n"


def _written(path, data, mode) -> str:
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(handle, "wb") as target:
        target.write(data)
    os.chmod(path, mode)
    return path


def _env(workspace) -> dict:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": workspace,
        "LC_ALL": "C",
    }


def argv(host, port, login, known_hosts, command, *, identity=None, legacy=None) -> list:
    name = _checked_host(host)
    number = _checked_port(port)
    user = _checked_login(login)
    line = _checked_command(command)
    _checked_text("known_hosts", known_hosts)
    options = OPTIONS if identity is not None else PASSWORD_OPTIONS
    result = [SSH_BINARY, "-F", CONFIG_FILE]
    for option in options + legacy_module.openssh_options(legacy):
        result.extend(["-o", option])
    result.extend(["-o", "UserKnownHostsFile=%s" % known_hosts])
    if identity is not None:
        result.extend(["-i", _checked_text("identity", identity)])
    result.extend(["-p", str(number), "%s@%s" % (user, name), line])
    return result


def _prepared(workspace, kind, credential) -> tuple:
    environment = _env(workspace)
    if kind == KIND_KEY:
        identity = _written(
            os.path.join(workspace, IDENTITY_NAME),
            _secret_bytes("private key", credential.use()),
            0o600,
        )
        return identity, environment
    secret = _written(
        os.path.join(workspace, SECRET_NAME),
        _secret_bytes("password", credential.use()),
        0o600,
    )
    askpass = _written(
        os.path.join(workspace, ASKPASS_NAME), ASKPASS_SCRIPT.encode("utf-8"), 0o700
    )
    environment["SSH_ASKPASS"] = askpass
    environment["SSH_ASKPASS_REQUIRE"] = "force"
    environment["DISPLAY"] = "none"
    environment["NETOPS_ASKPASS_FILE"] = secret
    return None, environment


def run_command(
    host,
    port,
    login,
    credential,
    host_key_line,
    command,
    *,
    legacy_ssh=None,
    timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
    run=subprocess.run,
    now=None,
) -> Result:
    name = _checked_host(host)
    number = _checked_port(port)
    line = _checked_command(command)
    kind = _checked_credential(credential)
    user = _checked_login(login if login is not None else getattr(credential, "login", None))
    profile = legacy_module.checked(legacy_ssh)
    seconds = _checked_timeout(timeout_seconds)
    clock = _clock(now)
    if not callable(run):
        raise SshError("run must be callable, got %s" % type(run).__name__)
    workspace = tempfile.mkdtemp(prefix=WORKSPACE_PREFIX)
    try:
        os.chmod(workspace, 0o700)
        known_hosts = hostkey.known_hosts_file(workspace, host_key_line)
        identity, environment = _prepared(workspace, kind, credential)
        call = argv(
            name, number, user, known_hosts, line, identity=identity, legacy=profile
        )
        started_at = _moment(clock)
        try:
            result = run(
                call, capture_output=True, timeout=seconds, env=environment, check=False
            )
        except subprocess.TimeoutExpired:
            raise SshError(
                "ssh to %s did not finish within %.1f seconds" % (name, seconds)
            ) from None
        except SshError:
            raise
        except Exception as error:
            raise SshError(
                "cannot run ssh to %s (%s)" % (name, type(error).__name__)
            ) from None
        finished_at = _moment(clock)
        if finished_at < started_at:
            finished_at = started_at
        data = getattr(result, "stdout", None)
        if not isinstance(data, (bytes, bytearray)):
            raise SshError(
                "the ssh runner must answer with bytes on stdout, got %s" % type(data).__name__
            )
        said = _said(result)
        code = getattr(result, "returncode", None)
        if (
            isinstance(code, bool)
            or not isinstance(code, int)
            or code == CLIENT_FAILURE_CODE
        ):
            detail = ", the client said: %s" % said if said else ""
            remedy = ""
            if profile is None and NEGOTIATION_MARKER in said:
                remedy = LEGACY_REMEDY % (name, ", ".join(legacy_module.PROFILES))
            raise SshError(
                "ssh to %s failed with exit code %s%s%s" % (name, code, detail, remedy),
                code if isinstance(code, int) and not isinstance(code, bool) else None,
                said,
            )
        return Result(
            rc=code,
            stdout=bytes(data),
            said=said,
            started_at=started_at,
            finished_at=finished_at,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
