from __future__ import annotations

import os
import pty
import select
import shutil
import signal
import tempfile
import time

from . import hostkey, legacy_ssh as legacy_module, ssh as ssh_module

TTY_OPTION = "-tt"
POLL_SECONDS = 0.2
KILL_AFTER_SECONDS = 2.0
REAP_STEP_SECONDS = 0.05
READ_BYTES = 4096
EXEC_FAILURE_CODE = 127


class SessionError(Exception):
    def __init__(self, message, transcript_bytes=0):
        super().__init__(message)
        self.transcript_bytes = transcript_bytes


def argv(host, port, login, known_hosts, *, identity=None, legacy=None) -> list:
    name = ssh_module._checked_host(host)
    number = ssh_module._checked_port(port)
    user = ssh_module._checked_login(login)
    ssh_module._checked_text("known_hosts", known_hosts)
    options = ssh_module.OPTIONS if identity is not None else ssh_module.PASSWORD_OPTIONS
    line = [ssh_module.SSH_BINARY, "-F", ssh_module.CONFIG_FILE, TTY_OPTION]
    for option in options + legacy_module.openssh_options(legacy):
        line.extend(["-o", option])
    line.extend(["-o", "UserKnownHostsFile=%s" % known_hosts])
    if identity is not None:
        line.extend(["-i", ssh_module._checked_text("identity", identity)])
    line.extend(["-p", str(number), "%s@%s" % (user, name)])
    return line


def _spawn(call, env) -> tuple:
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvpe(call[0], call, env)
        finally:
            os._exit(EXEC_FAILURE_CODE)
    return pid, fd


def _checked_patterns(patterns) -> tuple:
    if isinstance(patterns, (str, bytes, bytearray)):
        patterns = (patterns,)
    try:
        offered = list(patterns)
    except TypeError:
        raise SessionError(
            "expect waits for text patterns, got %s" % type(patterns).__name__
        ) from None
    prepared = []
    for pattern in offered:
        if isinstance(pattern, str):
            data = pattern.encode("utf-8")
        elif isinstance(pattern, (bytes, bytearray)):
            data = bytes(pattern)
        else:
            raise SessionError(
                "a pattern must be text or bytes, got %s" % type(pattern).__name__
            )
        if not data:
            raise SessionError("a pattern must not be empty")
        prepared.append(data)
    if not prepared:
        raise SessionError("expect needs at least one pattern to wait for")
    return tuple(prepared)


class Session:
    def __init__(
        self,
        host,
        port,
        login,
        credential,
        host_key_line,
        *,
        legacy_ssh=None,
        timeout_seconds=ssh_module.DEFAULT_TIMEOUT_SECONDS,
        spawn=None,
        now=None,
    ) -> None:
        name = ssh_module._checked_host(host)
        number = ssh_module._checked_port(port)
        kind = ssh_module._checked_credential(credential)
        user = ssh_module._checked_login(
            login if login is not None else getattr(credential, "login", None)
        )
        profile = legacy_module.checked(legacy_ssh)
        seconds = ssh_module._checked_timeout(timeout_seconds)
        clock = ssh_module._clock(now)
        start = _spawn if spawn is None else spawn
        if not callable(start):
            raise SessionError("spawn must be callable, got %s" % type(start).__name__)
        workspace = tempfile.mkdtemp(prefix=ssh_module.WORKSPACE_PREFIX)
        try:
            os.chmod(workspace, 0o700)
            known_hosts = hostkey.known_hosts_file(workspace, host_key_line)
            identity, environment = ssh_module._prepared(workspace, kind, credential)
            call = argv(name, number, user, known_hosts, identity=identity, legacy=profile)
            started_at = ssh_module._moment(clock)
            answer = start(call, environment)
            pid, fd = answer
            if not isinstance(pid, int) or not isinstance(fd, int):
                raise SessionError(
                    "spawn must answer with a process id and a file descriptor, got %r"
                    % (answer,)
                )
        except SessionError:
            shutil.rmtree(workspace, ignore_errors=True)
            raise
        except Exception as error:
            shutil.rmtree(workspace, ignore_errors=True)
            raise SessionError(
                "cannot open the session to %s (%s)" % (name, type(error).__name__)
            ) from None
        self.host = name
        self.port = number
        self.login = user
        self.argv = list(call)
        self.started_at = started_at
        self.timeout_seconds = seconds
        self.discarded_login_bytes = 0
        self.seen_bytes = 0
        self._workspace = workspace
        self._pid = pid
        self._fd = fd
        self._pending = b""
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace) -> bool:
        self.close()
        return False

    def _alive(self) -> None:
        if self._closed or self._fd is None:
            raise SessionError("the session to %s is already closed" % self.host)

    def discard(self, data) -> int:
        if isinstance(data, str):
            size = len(data.encode("utf-8"))
        elif isinstance(data, (bytes, bytearray)):
            size = len(data)
        else:
            raise SessionError("discard takes the bytes expect returned, got %s" % type(data).__name__)
        self.discarded_login_bytes += size
        return size

    def _match(self, buffer, patterns):
        best, index = None, -1
        for position, pattern in enumerate(patterns):
            found = buffer.find(pattern)
            if found < 0:
                continue
            if best is None or found < best or (found == best and position < index):
                best, index = found, position
        if best is None:
            return None
        return index, best + len(patterns[index])

    def expect(self, patterns, timeout_seconds) -> tuple:
        self._alive()
        awaited = _checked_patterns(patterns)
        seconds = ssh_module._checked_timeout(timeout_seconds)
        buffer = self._pending
        self._pending = b""
        deadline = time.monotonic() + seconds
        while True:
            found = self._match(buffer, awaited)
            if found is not None:
                index, cut = found
                consumed = buffer[:cut]
                self._pending = buffer[cut:]
                return index, consumed
            if time.monotonic() >= deadline:
                size = len(buffer)
                self.seen_bytes += size
                raise SessionError(
                    "%s did not answer any of the %d awaited pattern(s) within %.1f seconds,"
                    " %d byte(s) seen" % (self.host, len(awaited), seconds, size),
                    size,
                )
            step = min(POLL_SECONDS, max(0.0, deadline - time.monotonic()))
            try:
                ready, _, _ = select.select([self._fd], [], [], step)
            except OSError:
                ready = []
            if not ready:
                continue
            try:
                chunk = os.read(self._fd, READ_BYTES)
            except OSError:
                chunk = b""
            if not chunk:
                size = len(buffer)
                self.seen_bytes += size
                raise SessionError(
                    "the session to %s ended before any of the %d awaited pattern(s) matched,"
                    " %d byte(s) seen" % (self.host, len(awaited), size),
                    size,
                )
            buffer += chunk

    def send(self, line) -> None:
        self._alive()
        if not isinstance(line, str):
            raise SessionError("a session line must be text, got %s" % type(line).__name__)
        if any(mark in line for mark in ("\n", "\r", "\x00")):
            raise SessionError(
                "a session line must be a single line, the session adds the newline itself"
            )
        data = ("%s\n" % line).encode("utf-8")
        try:
            while data:
                written = os.write(self._fd, data)
                data = data[written:]
        except OSError as error:
            raise SessionError(
                "cannot write to the session to %s (%s)" % (self.host, type(error).__name__)
            ) from None

    def _reaped(self, pid) -> None:
        deadline = time.monotonic() + KILL_AFTER_SECONDS
        while True:
            try:
                done, _ = os.waitpid(pid, os.WNOHANG)
            except OSError:
                return
            if done == pid:
                return
            if time.monotonic() >= deadline:
                break
            time.sleep(REAP_STEP_SECONDS)
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._pending = b""
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        pid, self._pid = self._pid, None
        if pid:
            self._reaped(pid)
        shutil.rmtree(self._workspace, ignore_errors=True)

    def workspace(self) -> str:
        return self._workspace
