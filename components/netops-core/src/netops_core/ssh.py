from __future__ import annotations

import os
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from . import hostkey, legacy_ssh as legacy_module

SSH_BINARY = "ssh"
CONFIG_FILE = "/dev/null"
DEFAULT_TIMEOUT_SECONDS = 120.0
CAPTURE_MAX_BYTES = 16 * 1024 * 1024
STDERR_MAX_BYTES = 64 * 1024
READ_CHUNK = 65536
KILL_GRACE_SECONDS = 2.0
TERMINATE_GRACE_SECONDS = 0.5
SWEEP_STEP_SECONDS = 0.05
MOMENT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
WORKSPACE_PREFIX = "netops-core-"
IDENTITY_NAME = "identity"
SECRET_NAME = "secret"
ASKPASS_NAME = "askpass"
ASKPASS_SCRIPT = '#!/bin/sh\ncat "$NETOPS_ASKPASS_FILE"\n'
ASKPASS_PROGRAM_ENV = "NETOPS_ASKPASS_PROGRAM"
ASKPASS_REMEDY = (
    "; a deployment whose temporary directory is mounted noexec must ship an askpass program on an"
    " executable path and name it in %s" % ASKPASS_PROGRAM_ENV
)
KIND_PASSWORD = "password"
KIND_KEY = "ssh-key"
AUTH_KINDS = (KIND_PASSWORD, KIND_KEY)
SAID_CHARS = 200
NEGOTIATION_MARKER = "no matching"
CLIENT_FAILURE_CODE = 255
REASONS = (
    (NEGOTIATION_MARKER, "the client and the device share no algorithm the client accepts"),
    ("Permission denied", "the device refused the credential"),
    ("REMOTE HOST IDENTIFICATION HAS CHANGED", "the host key is not the pinned one"),
    ("Host key verification failed", "the host key is not the pinned one"),
    ("Connection refused", "the device refused the connection"),
    ("Connection reset", "the device closed the connection"),
    ("Connection closed", "the device closed the connection"),
    ("Connection timed out", "the connection timed out"),
    ("Operation timed out", "the connection timed out"),
    ("No route to host", "the device was not reachable"),
    ("Network is unreachable", "the device was not reachable"),
    ("Could not resolve hostname", "the name did not resolve"),
    ("Permission denied (publickey)", "the device refused the credential"),
    ("not found", "the remote path is not there"),
)
UNKNOWN_REASON = "the client reported a failure this transport does not recognize"
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


def reason(said) -> str:
    if not isinstance(said, str) or not said:
        return ""
    for marker, meaning in REASONS:
        if marker in said:
            return meaning
    return UNKNOWN_REASON


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


def _checked_capture(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SshError("capture_max_bytes must be a whole number of at least 1, got %r" % (value,))
    return value


def _own_group(pid):
    try:
        return pid if os.getpgid(pid) == pid else None
    except OSError:
        return None


def _signalled_group(group, number) -> None:
    if group is None:
        return
    try:
        os.killpg(group, number)
    except OSError:
        pass


def _group_alive(group) -> bool:
    try:
        os.killpg(group, 0)
    except OSError:
        return False
    return True


def _swept(group) -> None:
    if group is None or not _group_alive(group):
        return
    _signalled_group(group, signal.SIGTERM)
    deadline = time.monotonic() + TERMINATE_GRACE_SECONDS
    while _group_alive(group) and time.monotonic() < deadline:
        time.sleep(SWEEP_STEP_SECONDS)
    _signalled_group(group, signal.SIGKILL)


def _stopped(proc, group) -> None:
    for number, grace in (
        (signal.SIGTERM, TERMINATE_GRACE_SECONDS),
        (signal.SIGKILL, KILL_GRACE_SECONDS),
    ):
        _signalled_group(group, number)
        try:
            proc.send_signal(number)
        except (OSError, ValueError):
            pass
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass


def _remaining(deadline):
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


def _run_capped(call, max_bytes, *, timeout, env, stdin_bytes):
    deadline = None if timeout is None else time.monotonic() + timeout
    proc = subprocess.Popen(
        call,
        stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    group = _own_group(proc.pid)
    finished = False
    try:
        if stdin_bytes is not None:
            try:
                proc.stdin.write(stdin_bytes)
            except OSError:
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
        out = bytearray()
        err = bytearray()
        open_streams = 2
        overrun = False
        selector = selectors.DefaultSelector()
        try:
            selector.register(proc.stdout.fileno(), selectors.EVENT_READ, "out")
            selector.register(proc.stderr.fileno(), selectors.EVENT_READ, "err")
            while open_streams and not overrun:
                remaining = _remaining(deadline)
                if remaining is not None and remaining <= 0:
                    raise subprocess.TimeoutExpired(call, timeout)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj, READ_CHUNK)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        open_streams -= 1
                        continue
                    if key.data == "out":
                        out += chunk
                        if len(out) > max_bytes:
                            overrun = True
                            break
                    elif len(err) < STDERR_MAX_BYTES:
                        err += chunk[: STDERR_MAX_BYTES - len(err)]
        finally:
            selector.close()
            proc.stdout.close()
            proc.stderr.close()
        if overrun:
            raise SshError(
                "the client produced more than %d bytes on stdout and was stopped" % max_bytes
            )
        code = proc.wait(timeout=_remaining(deadline))
        finished = True
        _swept(group)
        return subprocess.CompletedProcess(call, code, bytes(out), bytes(err))
    finally:
        if not finished:
            _stopped(proc, group)


def _capped_runner(max_bytes):
    def runner(call, *, capture_output=True, timeout=None, env=None, check=False, input=None):
        return _run_capped(call, max_bytes, timeout=timeout, env=env, stdin_bytes=input)

    return runner


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


def _named_askpass(named) -> str:
    try:
        information = os.stat(named)
    except OSError:
        raise SshError(
            "%s names %r, which is not a file this process can read"
            % (ASKPASS_PROGRAM_ENV, named)
        ) from None
    if not stat.S_ISREG(information.st_mode):
        raise SshError(
            "%s names %r, which is not a regular file" % (ASKPASS_PROGRAM_ENV, named)
        )
    if information.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SshError(
            "%s names %r, which is writable by group or other; the program that is handed the"
            " password must not be" % (ASKPASS_PROGRAM_ENV, named)
        )
    if not os.access(named, os.X_OK):
        raise SshError(
            "%s names %r, which this process cannot execute" % (ASKPASS_PROGRAM_ENV, named)
        )
    return named


def _askpass(workspace) -> str:
    named = os.environ.get(ASKPASS_PROGRAM_ENV)
    if named is not None:
        return _named_askpass(named)
    written = _written(
        os.path.join(workspace, ASKPASS_NAME), ASKPASS_SCRIPT.encode("utf-8"), 0o700
    )
    if not os.access(written, os.X_OK):
        raise SshError(
            "the askpass program written into %s cannot be executed, so a password cannot be"
            " handed to the client%s" % (workspace, ASKPASS_REMEDY)
        )
    return written


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
    environment["SSH_ASKPASS"] = _askpass(workspace)
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
    capture_max_bytes=CAPTURE_MAX_BYTES,
    run=None,
    now=None,
) -> Result:
    name = _checked_host(host)
    number = _checked_port(port)
    line = _checked_command(command)
    kind = _checked_credential(credential)
    user = _checked_login(login if login is not None else getattr(credential, "login", None))
    profile = legacy_module.checked(legacy_ssh)
    seconds = _checked_timeout(timeout_seconds)
    budget = _checked_capture(capture_max_bytes)
    clock = _clock(now)
    runner = run if run is not None else _capped_runner(budget)
    if not callable(runner):
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
            result = runner(
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
            detail = "; %s" % reason(said) if said else ""
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
