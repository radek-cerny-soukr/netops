from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from . import hostkey, legacy_ssh as legacy_module, ssh as ssh_module

SFTP_BINARY = "sftp"
CONFIG_FILE = ssh_module.CONFIG_FILE
DEFAULT_TIMEOUT_SECONDS = 60.0
WORKSPACE_PREFIX = ssh_module.WORKSPACE_PREFIX
LIST_COMMAND = 'ls -ln "%s"\n'
ECHO_PREFIX = "sftp> "
PROGRESS_PREFIX = "Connected to "
LISTING_MAX_BYTES = 256 * 1024
PATH_MAX_CHARS = 2_000
FORBIDDEN_PATH_MARKS = ('"', "\n", "\r", "\x00")
KIND_FILE = "file"
KIND_DIRECTORY = "directory"
KIND_SYMLINK = "symlink"
KIND_OTHER = "other"
TYPE_CHARACTERS = {"-": KIND_FILE, "d": KIND_DIRECTORY, "l": KIND_SYMLINK}
MODE_LETTERS = (
    ("r", 0o400), ("w", 0o200), ("x", 0o100),
    ("r", 0o040), ("w", 0o020), ("x", 0o010),
    ("r", 0o004), ("w", 0o002), ("x", 0o001),
)
MODE_SPECIAL = {
    2: {"s": 0o4100, "S": 0o4000},
    5: {"s": 0o2010, "S": 0o2000},
    8: {"t": 0o1001, "T": 0o1000},
}
MODE_LENGTH = 10
LISTING_FIELDS = 6
TIME_FIELDS = 3


SftpError = ssh_module.SshError


@dataclass(frozen=True)
class Entry:
    kind: str
    mode: int | None
    size: int | None
    modified_ls: str | None
    name: str | None
    entry_count: int | None
    said: str
    started_at: str
    finished_at: str


def _checked_remote_path(value) -> str:
    path = ssh_module._checked_text("remote_path", value)
    if not path.startswith("/"):
        raise SftpError("remote_path must be an absolute POSIX path, got %r" % (value,))
    if len(path) > PATH_MAX_CHARS:
        raise SftpError(
            "remote_path must be at most %d characters, got %d"
            % (PATH_MAX_CHARS, len(path))
        )
    if any(mark in path for mark in FORBIDDEN_PATH_MARKS):
        raise SftpError(
            "remote_path must not carry a quote or a line break: the sftp batch is one line"
        )
    if path != path.strip():
        raise SftpError("remote_path must not begin or end with whitespace, got %r" % (value,))
    if any(part == ".." for part in path.split("/")):
        raise SftpError("remote_path must not walk upwards, got %r" % (value,))
    return path


def argv(host, port, login, known_hosts, *, identity=None, legacy=None) -> list:
    name = ssh_module._checked_host(host)
    number = ssh_module._checked_port(port)
    user = ssh_module._checked_login(login)
    ssh_module._checked_text("known_hosts", known_hosts)
    options = ssh_module.OPTIONS if identity is not None else ssh_module.PASSWORD_OPTIONS
    result = [SFTP_BINARY, "-F", CONFIG_FILE]
    for option in options + legacy_module.openssh_options(legacy):
        result.extend(["-o", option])
    result.extend(["-o", "UserKnownHostsFile=%s" % known_hosts])
    if identity is not None:
        result.extend(["-i", ssh_module._checked_text("identity", identity)])
    result.extend(["-P", str(number), "%s@%s" % (user, name)])
    return result


def _mode_bits(text):
    if len(text) != MODE_LENGTH:
        return None
    value = 0
    for index, (letter, bit) in enumerate(MODE_LETTERS):
        character = text[index + 1]
        if character == letter:
            value |= bit
        elif character == "-":
            continue
        else:
            special = MODE_SPECIAL.get(index, {})
            if character not in special:
                return None
            value |= special[character]
    return value


def _listed(line):
    fields = line.split(None, LISTING_FIELDS - 1)
    if len(fields) != LISTING_FIELDS:
        return None
    permissions, _links, _owner, _group, size, tail = fields
    mode = _mode_bits(permissions)
    if mode is None:
        return None
    rest = tail.split(None, TIME_FIELDS)
    if len(rest) != TIME_FIELDS + 1:
        return None
    try:
        length = int(size)
    except ValueError:
        return None
    return (
        TYPE_CHARACTERS.get(permissions[0], KIND_OTHER),
        mode,
        length,
        " ".join(rest[:TIME_FIELDS]),
        rest[TIME_FIELDS],
    )


def _listing(data) -> list:
    if len(data) > LISTING_MAX_BYTES:
        raise SftpError(
            "the sftp listing is larger than %d bytes and was not read" % LISTING_MAX_BYTES
        )
    lines = []
    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith(ECHO_PREFIX) or not line.strip():
            continue
        lines.append(line)
    return lines


def _reported(result) -> list:
    data = getattr(result, "stderr", None)
    if not isinstance(data, (bytes, bytearray)):
        return []
    return [
        line.strip()
        for line in bytes(data).decode("utf-8", "replace").splitlines()
        if line.strip() and not line.strip().startswith(PROGRESS_PREFIX)
    ]


def stat(
    host,
    port,
    login,
    credential,
    host_key_line,
    remote_path,
    *,
    legacy_ssh=None,
    timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
    capture_max_bytes=ssh_module.CAPTURE_MAX_BYTES,
    run=None,
    now=None,
) -> Entry:
    name = ssh_module._checked_host(host)
    number = ssh_module._checked_port(port)
    path = _checked_remote_path(remote_path)
    kind = ssh_module._checked_credential(credential)
    user = ssh_module._checked_login(
        login if login is not None else getattr(credential, "login", None)
    )
    profile = legacy_module.checked(legacy_ssh)
    seconds = ssh_module._checked_timeout(timeout_seconds)
    budget = ssh_module._checked_capture(capture_max_bytes)
    clock = ssh_module._clock(now)
    runner = run if run is not None else ssh_module._capped_runner(budget)
    if not callable(runner):
        raise SftpError("run must be callable, got %s" % type(run).__name__)
    workspace = tempfile.mkdtemp(prefix=WORKSPACE_PREFIX)
    try:
        os.chmod(workspace, 0o700)
        known_hosts = hostkey.known_hosts_file(workspace, host_key_line)
        identity, environment = ssh_module._prepared(workspace, kind, credential)
        call = argv(name, number, user, known_hosts, identity=identity, legacy=profile)
        batch = (LIST_COMMAND % path).encode("utf-8")
        started_at = ssh_module._moment(clock)
        try:
            result = runner(
                call,
                input=batch,
                capture_output=True,
                timeout=seconds,
                env=environment,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SftpError(
                "sftp to %s did not finish within %.1f seconds" % (name, seconds)
            ) from None
        except ssh_module.SshError:
            raise
        except Exception as error:
            raise SftpError(
                "cannot run sftp to %s (%s)" % (name, type(error).__name__)
            ) from None
        finished_at = ssh_module._moment(clock)
        if finished_at < started_at:
            finished_at = started_at
        data = getattr(result, "stdout", None)
        if not isinstance(data, (bytes, bytearray)):
            raise SftpError(
                "the sftp runner must answer with bytes on stdout, got %s" % type(data).__name__
            )
        said = ssh_module._said(result)
        code = getattr(result, "returncode", None)
        if isinstance(code, bool) or not isinstance(code, int) or code != 0:
            detail = "; %s" % ssh_module.reason(said) if said else ""
            remedy = ""
            if profile is None and ssh_module.NEGOTIATION_MARKER in said:
                remedy = ssh_module.LEGACY_REMEDY % (
                    name, ", ".join(legacy_module.PROFILES),
                )
            raise SftpError(
                "sftp to %s failed with exit code %s%s%s" % (name, code, detail, remedy),
                code if isinstance(code, int) and not isinstance(code, bool) else None,
                said,
            )
        lines = _listing(bytes(data))
        reported = _reported(result)
        if not lines:
            if reported:
                raise SftpError(
                    "sftp on %s could not list the path; %s" % (name, ssh_module.reason(said)),
                    code,
                    said,
                )
            return Entry(
                kind=KIND_DIRECTORY,
                mode=None,
                size=None,
                modified_ls=None,
                name=None,
                entry_count=0,
                said=said,
                started_at=started_at,
                finished_at=finished_at,
            )
        if len(lines) == 1:
            listed = _listed(lines[0])
            if listed is None:
                raise SftpError(
                    "sftp on %s answered a listing line this parser does not know" % name,
                    code,
                    said,
                )
            if listed[4] == path:
                return Entry(
                    kind=listed[0],
                    mode=listed[1],
                    size=listed[2],
                    modified_ls=listed[3],
                    name=listed[4],
                    entry_count=None,
                    said=said,
                    started_at=started_at,
                    finished_at=finished_at,
                )
        return Entry(
            kind=KIND_DIRECTORY,
            mode=None,
            size=None,
            modified_ls=None,
            name=None,
            entry_count=len(lines),
            said=said,
            started_at=started_at,
            finished_at=finished_at,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
