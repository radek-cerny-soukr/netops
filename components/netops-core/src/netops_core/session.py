from __future__ import annotations

import os
import re
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass

from . import hostkey, legacy_ssh as legacy_module, platforms, ssh as ssh_module

TTY_OPTION = "-tt"
POLL_SECONDS = 0.2
KILL_AFTER_SECONDS = 2.0
REAP_STEP_SECONDS = 0.05
READ_BYTES = 4096


class SessionError(Exception):
    def __init__(self, message, transcript_bytes=0, final="", *, code=None):
        super().__init__(message)
        self.transcript_bytes = transcript_bytes
        # The ended client's closing message or fixed diagnosis, kept local for classification.
        self.final = final
        self.code = code


def argv(host, port, login, known_hosts, *, identity=None, legacy=None) -> list:
    name = ssh_module._checked_host(host)
    number = ssh_module._checked_port(port)
    user = ssh_module._checked_login(login)
    ssh_module._checked_client_path("known_hosts", known_hosts)
    options = ssh_module.OPTIONS if identity is not None else ssh_module.PASSWORD_OPTIONS
    line = [ssh_module.SSH_BINARY, "-F", ssh_module.CONFIG_FILE, TTY_OPTION]
    for option in options + legacy_module.openssh_options(legacy):
        line.extend(["-o", option])
    for option in ssh_module.known_hosts_options(known_hosts):
        line.extend(["-o", option])
    if identity is not None:
        line.extend(["-i", ssh_module._checked_client_path("identity", identity)])
    line.extend(["-p", str(number), "%s@%s" % (user, name)])
    return line


LAUNCHER_VARIABLE = b"NETOPS_SPAWN_LAUNCHER"
LAUNCHER = "\n".join((
    "import fcntl, os, sys, termios",
    "env = dict(os.environb)",
    "report, kept, ctype = env.pop(%r).partition(b'=')" % LAUNCHER_VARIABLE,
    "if kept:",
    "    env[b'LC_CTYPE'] = ctype",
    "else:",
    "    env.pop(b'LC_CTYPE', None)",
    "report = int(report)",
    "os.set_inheritable(report, False)",
    "try:",
    "    fcntl.ioctl(0, termios.TIOCSCTTY, 0)",
    "    os.execvpe(sys.argv[1], sys.argv[1:], env)",
    "except OSError as error:",
    "    os.write(report, b'%d=%s' % (error.errno, os.fsencode(error.filename or '')))",
    "os._exit(127)",
))


class _Client(subprocess.Popen):
    """The started client. The session waits for it by its process id, so it is not reaped here."""

    def __del__(self):
        pass


def _launch_error(report) -> OSError:
    number, _, name = report.partition(b"=")
    number = int(number)
    if name:
        return OSError(number, os.strerror(number), os.fsdecode(name))
    return OSError(number, os.strerror(number))


def _spawn(call, env) -> tuple:
    """Start call on a new pty as the leader of a new session, without forking in Python.

    subprocess starts a fixed launcher with setsid() and the pty terminal as stdin, stdout and
    stderr, and closes every other descriptor in the child (close_fds=True), so nothing this
    process opens meanwhile reaches the client. The launcher makes the terminal its controlling
    terminal and executes call with exactly env; the program is searched only on the PATH of env.
    LAUNCHER_VARIABLE carries the descriptor on which the launcher reports a failed exec, raised
    here as the same OSError, and the LC_CTYPE of env, which the launcher's interpreter may
    coerce. Both pty ends are close-on-exec in this process.
    """
    if not call:
        raise ValueError("the client needs a program to start")
    encoded = {os.fsencode(name): os.fsencode(value) for name, value in env.items()}
    ctype = encoded.get(b"LC_CTYPE")
    fd, terminal = os.openpty()
    pid = None
    client = None
    try:
        report, written = os.pipe()
        try:
            try:
                client = _Client(
                    [sys.executable, "-I", "-S", "-B", "-c", LAUNCHER, *call],
                    stdin=terminal,
                    stdout=terminal,
                    stderr=terminal,
                    env={
                        **encoded,
                        LAUNCHER_VARIABLE: b"%d" % written + (b"" if ctype is None else b"=" + ctype),
                    },
                    close_fds=True,
                    pass_fds=(written,),
                    start_new_session=True,
                )
            finally:
                os.close(written)
            failure = b""
            while True:
                chunk = os.read(report, READ_BYTES)
                if not chunk:
                    break
                failure += chunk
        finally:
            os.close(report)
        if failure:
            client.wait()
            raise _launch_error(failure)
        pid = client.pid
    finally:
        os.close(terminal)
        if pid is None:
            os.close(fd)
            if client is not None and client.returncode is None:
                ssh_module._stopped(client, ssh_module._own_group(client.pid))
    return pid, fd


def _waited(pid, seconds) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except OSError:
            return True
        if done == pid:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(REAP_STEP_SECONDS)


def _signalled(pid, number) -> None:
    try:
        os.kill(pid, number)
    except OSError:
        pass


def _checked_patterns(patterns) -> tuple:
    if isinstance(patterns, (str, bytes, bytearray, re.Pattern)):
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
            try:
                data = pattern.encode("utf-8")
            except UnicodeEncodeError:
                raise SessionError("a text pattern must be valid Unicode") from None
        elif isinstance(pattern, (bytes, bytearray)):
            data = bytes(pattern)
        elif isinstance(pattern, re.Pattern) and isinstance(pattern.pattern, bytes):
            data = pattern
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
    def _terminal_options(self, workspace):
        return ()

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
        capture_max_bytes=ssh_module.CAPTURE_MAX_BYTES,
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
        budget = ssh_module._checked_capture(capture_max_bytes)
        clock = ssh_module._clock(now)
        start = _spawn if spawn is None else spawn
        if not callable(start):
            raise SessionError("spawn must be callable, got %s" % type(start).__name__)
        ssh_module._abandoned_removed()
        workspace = tempfile.mkdtemp(prefix=ssh_module.WORKSPACE_PREFIX)
        owner = None
        try:
            os.chmod(workspace, 0o700)
            owner = ssh_module._claimed(workspace)
            known_hosts = hostkey.known_hosts_file(workspace, host_key_line)
            identity, environment = ssh_module._prepared(workspace, kind, credential)
            call = argv(name, number, user, known_hosts, identity=identity, legacy=profile)
            call[1:1] = self._terminal_options(workspace)
            started_at = ssh_module._moment(clock)
            answer = start(call, environment)
            pid, fd = answer
            if not isinstance(pid, int) or not isinstance(fd, int):
                raise SessionError(
                    "spawn must answer with a process id and a file descriptor, got %r"
                    % (answer,)
                )
        except SessionError:
            ssh_module._released(workspace, owner)
            raise
        except Exception as error:
            ssh_module._released(workspace, owner)
            raise SessionError(
                "cannot open the session to %s (%s)" % (name, type(error).__name__)
            ) from None
        except BaseException:
            ssh_module._released(workspace, owner)
            raise
        self.host = name
        self.port = number
        self.login = user
        self.argv = list(call)
        self.started_at = started_at
        self.timeout_seconds = seconds
        self.max_transcript_bytes = budget
        self.discarded_login_bytes = 0
        self.seen_bytes = 0
        self._workspace = workspace
        self._owner = owner
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
        best, cut, index = None, None, -1
        for position, pattern in enumerate(patterns):
            if isinstance(pattern, re.Pattern):
                match = pattern.search(buffer)
                if match is None:
                    continue
                found, end = match.span()
            else:
                found = buffer.find(pattern)
                if found < 0:
                    continue
                end = found + len(pattern)
            if best is None or found < best or (found == best and position < index):
                best, cut, index = found, end, position
        if best is None:
            return None
        return index, cut

    def expect(self, patterns, timeout_seconds, *, quiet_seconds=None) -> tuple:
        """Consume through a match, optionally waiting for silence and rematching after new bytes."""
        self._alive()
        awaited = _checked_patterns(patterns)
        seconds = ssh_module._checked_timeout(timeout_seconds)
        quiet = 0.0 if quiet_seconds is None else ssh_module._checked_timeout(quiet_seconds)
        buffer = self._pending
        self._pending = b""
        deadline = time.monotonic() + seconds
        while True:
            found = self._match(buffer, awaited)
            if found is not None and not quiet:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                size = len(buffer)
                self.seen_bytes += size
                raise SessionError(
                    "%s did not answer any of the %d awaited pattern(s) within %.1f seconds,"
                    " %d byte(s) seen" % (self.host, len(awaited), seconds, size),
                    size,
                )
            step = min(quiet if found is not None else POLL_SECONDS, remaining)
            try:
                ready, _, _ = select.select([self._fd], [], [], step)
            except OSError:
                continue
            if not ready:
                if found is not None and step == quiet:
                    break
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
                    ssh_module.final_said(buffer),
                )
            buffer += chunk
            if len(buffer) > self.max_transcript_bytes:
                size = len(buffer)
                self.seen_bytes += size
                raise SessionError(
                    "the session to %s produced more than %d bytes without matching any of the"
                    " %d awaited pattern(s) and was stopped"
                    % (self.host, self.max_transcript_bytes, len(awaited)),
                    size,
                )
        index, cut = found
        self._pending = buffer[cut:]
        return index, buffer[:cut]

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
                if written <= 0:
                    raise OSError("short write to the session")
                data = data[written:]
        except OSError as error:
            raise SessionError(
                "cannot write to the session to %s (%s)" % (self.host, type(error).__name__)
            ) from None

    def interrupt(self) -> None:
        self._alive()
        try:
            if os.write(self._fd, b"\x03") != 1:
                raise SessionError("the terminal interrupt was not sent")
        except OSError:
            raise SessionError("the terminal interrupt could not be sent") from None

    def _reaped(self, pid) -> None:
        group = ssh_module._own_group(pid)
        gone = _waited(pid, KILL_AFTER_SECONDS)
        if not gone:
            ssh_module._signalled_group(group, signal.SIGTERM)
            _signalled(pid, signal.SIGTERM)
            gone = _waited(pid, ssh_module.TERMINATE_GRACE_SECONDS)
        if not gone:
            ssh_module._signalled_group(group, signal.SIGKILL)
            _signalled(pid, signal.SIGKILL)
            _waited(pid, KILL_AFTER_SECONDS)
        ssh_module._swept(group)

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
        try:
            if pid:
                self._reaped(pid)
        finally:
            owner, self._owner = self._owner, None
            ssh_module._released(self._workspace, owner)

    def workspace(self) -> str:
        return self._workspace


FORTINET_LOGIN_SECONDS = 20.0
FORTINET_IDLE_SECONDS = 15.0
FORTINET_MAX_PAGES = 128
FORTINET_QUIET_SECONDS = 0.12
FORTINET_COMMAND_MAX_BYTES = 16384
_PROMPT_WINDOW = 512
_LINE_OVERLAP = 64
_FORTINET_HOST = rb"[A-Za-z0-9_.+-]{1,128}"
_FORTINET_CONTEXT = rb"(?: \((?P<context>[ -'*-~]{1,128})\))?"
_FORTINET_NAVIGATION = frozenset(("config", "edit", "next", "end", "abort"))
_FORTINET_LOGIN_CODES = {
    "the device refused the credential": "auth",
    "the device requested an unsupported non-password authentication prompt": "auth",
    "the host key is not the pinned one": "host_key",
    "the client and the device share no algorithm the client accepts": "negotiation",
}
_PAGER_TAIL = re.compile(rb"(?:\x1b\[[0-9;]{1,8}m)?--More--(?:\x1b\[[0-9;]{1,8}m)?[ \t]{0,8}\Z")
_PAGER_ERASE = re.compile(rb"(?:\r {1,256}\r|\r?\x1b\[[012]?K|(?P<back>\x08{1,32}) {1,32}(?P=back))")
_PAGER_ERASE_PREFIX = re.compile(rb"(?:\r {0,256}|\r?\x1b(?:\[[012]?)?|\x08{1,32}(?: {1,32}\x08{0,32})?)\Z")
_FORTINET_REFUSAL = re.compile(
    rb"(?i)[ \t]*(?:[0-9]{1,8}:[ \t]+)?(?:Unknown action(?:[ \t]+[0-9]+)?(?:[ \t]*\Z)"
    rb"|Command fail(?:\.|[ \t]*\Z)|command parse error\b|Parsing error\b|value parse error\b"
    rb"|permission denied\b|no permission\b|invalid (?:or incomplete )?command\b|incomplete command\b"
    rb"|entry is not found[ \t]*\Z|(?:%[ \t]+)?Inbound soft reconfiguration not enabled[ \t]*\Z)"
)


@dataclass(frozen=True)
class FortinetResult(ssh_module.Result):
    context: str | None = None
    continuation: bool = False
    refusal: str | None = None


def _fortinet_prompt(platform, hostname=None):
    if platform == "fortiadc":
        role, suffix = rb"(?:\([PSMI]\) )?", b""
    else:
        role, suffix = b"", rb"(?:\((?:Primary|Secondary)\))?"
    name = _FORTINET_HOST if hostname is None else re.escape(hostname)
    return re.compile(rb"(?P<identity>" + role + rb"(?P<host>" + name + rb")" + suffix + rb")"
                      + _FORTINET_CONTEXT + rb"(?P<ending> [#$][ \t]{0,8})")


class _FortinetOutput:
    """Keep the unfinished line's framing and stream completed body bytes."""

    def __init__(self, pattern, *, command=None, previous=None, consumer=None, allow_continuation=False,
                 exact_prompt=None, keep_refusal=False):
        self.pattern = pattern
        self.command = command
        self.previous = previous
        self.consumer = consumer
        self.allow_continuation = allow_continuation
        self.exact_prompt = exact_prompt
        self.keep_refusal = keep_refusal
        self.pending = b""
        self.erase = None
        self.line_head = True
        self.refused = False
        self.output = bytearray()
        self.probing = False
        self.probe_line = None

    def _body(self, data, complete):
        if self.previous is None or (self.refused and not self.keep_refusal):
            return
        if self.line_head:
            if self.command is not None:
                # FortiOS can insert a space and backspace when the echoed command wraps.
                if complete and data.replace(b" \x08", b"") in (self.command, self.previous + self.command):
                    self.command = None
                    return
                if data:
                    self.command = None
            if _FORTINET_REFUSAL.match(data):
                self.refused = True
                if not self.keep_refusal:
                    self.output.clear()
                    return
        delivered = data + b"\n" if complete else data
        if self.consumer is None:
            self.output.extend(delivered)
        else:
            try:
                self.consumer(delivered)
            except ssh_module.OutputLimitError:
                raise ssh_module.OutputLimitError() from None
            except Exception:
                raise ssh_module.OutputConsumerError() from None

    def feed(self, chunk):
        if self.erase is not None:
            chunk = self.erase + chunk
            erased = _PAGER_ERASE.match(chunk)
            if erased is not None:
                chunk = chunk[erased.end():]
            elif _PAGER_ERASE_PREFIX.fullmatch(chunk):
                self.erase = chunk
                return
            self.erase = None
        *lines, self.pending = (self.pending + chunk).split(b"\n")
        for line in lines:
            line = line.rstrip(b"\r")
            self._flush_probe_line()
            if self.probing and self.line_head and self._match_prompt(line) is not None:
                self.probe_line = line
            else:
                self._body(line, complete=True)
            self.line_head = True
        window = _PROMPT_WINDOW + (len(self.command) if self.command is not None else 0)
        if len(self.pending) > window:
            self._flush_probe_line()
            self._body(self.pending[:-_LINE_OVERLAP], complete=False)
            self.pending = self.pending[-_LINE_OVERLAP:]
            self.line_head = False

    def _flush_probe_line(self):
        if self.probe_line is not None:
            self._body(self.probe_line, complete=True)
            self.probe_line = None

    def _match_prompt(self, data):
        if self.exact_prompt is None or data == self.exact_prompt:
            return self.pattern.fullmatch(data)
        return None

    def prompt(self):
        if self.line_head and self.erase is None:
            return self._match_prompt(self.pending)
        return None

    def continuation(self):
        return self.allow_continuation and self.line_head and self.pending == b"> " and self.erase is None

    def pager(self):
        if self.erase is not None:
            return None
        pending = self.pending.removesuffix(b"\r")
        if self.line_head and self.command is not None and pending in (self.command, self.previous + self.command):
            return None
        return _PAGER_TAIL.search(pending)

    def advance_page(self, marker):
        self._flush_probe_line()
        # A pager reached after an apparent prompt can consume its queued newline.
        self.probing = False
        self.erase = self.pending[marker.end():]
        self.pending = self.pending[:marker.start()]


def _fortinet_limits(timeout, idle, capture, pages):
    try:
        seconds = ssh_module._checked_timeout(timeout)
        idle_seconds = ssh_module._checked_timeout(idle)
        budget = ssh_module._checked_capture(capture)
    except ssh_module.SshError:
        raise SessionError("Fortinet timeouts and capture_max_bytes must be positive",
                           code="invalid_limits") from None
    if type(pages) is not int or pages < 0:
        raise SessionError("max_pages must be a non-negative integer", code="invalid_limits")
    return seconds, idle_seconds, budget, pages


class _FortinetSession(Session):
    def _terminal_options(self, workspace):
        self._client_log = os.path.join(workspace, "client.log")
        # Separate OpenSSH diagnostics from the remote terminal and its banner.
        return ("-e", "none", "-o", "UpdateHostKeys=no", "-o", "LogLevel=ERROR", "-E", self._client_log)

    def __init__(self, platform, address, port, login, credential, key_line, legacy, limits, login_seconds):
        self._platform = platform
        self._limits = limits
        self._command_lock = threading.Lock()
        self._timestamp = ssh_module._clock(None)
        try:
            connect = ssh_module._checked_timeout(login_seconds)
            super().__init__(address, port, login, credential, key_line, legacy_ssh=legacy,
                             timeout_seconds=limits[0], capture_max_bytes=limits[2])
        except (ssh_module.SshError, legacy_module.LegacySshError):
            raise SessionError("invalid Fortinet SSH login, credential, profile or login timeout",
                               code="invalid_session") from None
        try:
            os.set_blocking(self._fd, False)
            initial = _FortinetOutput(_fortinet_prompt(platform))
            try:
                match = self._read_output(initial, time.monotonic() + connect, connect, limits[2], None)
            except SessionError as error:
                if error.code not in ("timeout", "disconnected"):
                    raise
                detail, diagnosis = self._login_diagnostic()
                raise SessionError("%s; %s" % (error, detail), error.transcript_bytes,
                                   final=diagnosis, code=_FORTINET_LOGIN_CODES.get(diagnosis, error.code)) from None
            self.discarded_login_bytes = self.seen_bytes
            self._prompt_pattern = re.compile(re.escape(match["identity"]) + _FORTINET_CONTEXT
                                              + re.escape(match["ending"]))
            self._accept_prompt(match)
        except OSError:
            self.close()
            raise SessionError("cannot configure the Fortinet SSH terminal", code="terminal") from None
        except BaseException:
            self.close()
            raise

    def _login_diagnostic(self):
        try:
            closing = ssh_module.final_said(ssh_module._client_log_tail(self._client_log))
        except OSError:
            closing = ""
        diagnosis = ssh_module.reason(closing)
        reachability = "check reachability and the SSH port"
        if diagnosis in ("", ssh_module.UNKNOWN_REASON):
            return reachability, ""
        if diagnosis in ("the device refused the connection", "the connection timed out"):
            return "%s; %s" % (diagnosis, reachability), diagnosis
        return diagnosis, diagnosis

    def _accept_prompt(self, match):
        self._context_prompt = self._last_prompt = match[0]
        self.context = match["context"].decode("ascii") if match["context"] is not None else None

    def _expected_prompt(self, command, navigate=None):
        if navigate is None:
            verb = command.lstrip().partition(" ")[0]
            navigate = verb in _FORTINET_NAVIGATION
        return None if navigate else self._context_prompt

    def _terminal_ready(self, *, read, timeout):
        try:
            readers, writers, _ = select.select([self._fd] if read else [], [] if read else [self._fd],
                                                [], timeout)
        except (OSError, ValueError):
            raise SessionError("Fortinet SSH terminal is unavailable", code="terminal") from None
        return bool(readers or writers)

    def _write_input(self, data, deadline):
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._terminal_ready(read=False, timeout=remaining):
                raise SessionError("Fortinet SSH timed out sending terminal input", code="timeout")
            try:
                sent = os.write(self._fd, data)
            except BlockingIOError:
                continue
            except OSError:
                sent = 0
            if not sent:
                raise SessionError("Fortinet SSH could not send terminal input", code="disconnected")
            data = data[sent:]

    def _read_output(self, output, deadline, idle, budget, max_pages):
        received = pages = 0
        last_read = time.monotonic()
        while True:
            now = time.monotonic()
            if now >= deadline:
                raise SessionError("Fortinet SSH timed out waiting for a prompt", received, code="timeout")
            if now >= last_read + idle:
                raise SessionError("Fortinet SSH reached its idle timeout", received, code="idle_timeout")
            match = output.prompt()
            continuation = output.continuation()
            pager = output.pager() if max_pages is not None else None
            if match is not None and output.probe_line == match[0]:
                return match
            waiting_for_prompt = match is not None and not output.probing
            waiting_for_quiet = waiting_for_prompt or continuation or pager is not None
            until = min(deadline, last_read + idle)
            if waiting_for_quiet:
                until = min(until, last_read + FORTINET_QUIET_SECONDS)
            if not self._terminal_ready(read=True, timeout=max(0, until - now)):
                now = time.monotonic()
                if (not waiting_for_quiet or now < last_read + FORTINET_QUIET_SECONDS
                        or now >= min(deadline, last_read + idle)):
                    continue
                if continuation:
                    output._flush_probe_line()
                    return None
                if waiting_for_prompt:
                    if output.previous is None:
                        return match
                    # A prompt-shaped output line can only start the check.
                    # The empty input is queued behind the command and must
                    # produce the same prompt with no output between them.
                    self._write_input(b"\n", min(deadline, last_read + idle))
                    output.probing = True
                    continue
                if pages >= max_pages:
                    raise SessionError("Fortinet SSH exceeded its pager limit", received, code="page_limit")
                pages += 1
                output.advance_page(pager)
                self._write_input(b" ", min(deadline, last_read + idle))
                continue
            try:
                chunk = os.read(self._fd, READ_BYTES)
            except BlockingIOError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                raise SessionError("Fortinet SSH disconnected before a prompt", received, code="disconnected")
            last_read = time.monotonic()
            received += len(chunk)
            self.seen_bytes += len(chunk)
            if received > budget:
                raise SessionError("Fortinet SSH exceeded its capture limit", received, code="output_limit")
            output.feed(chunk)

    def run(self, command, *, stdout_consumer=None, timeout_seconds=None, idle_timeout_seconds=None,
            capture_max_bytes=None, max_pages=None) -> FortinetResult:
        self._alive()
        if not isinstance(command, str) or any(not char.isprintable() for char in command):
            raise SessionError("Fortinet SSH input must be a single line of printable text", code="invalid_command")
        data = command.encode("utf-8")
        if len(data) > FORTINET_COMMAND_MAX_BYTES:
            raise SessionError("Fortinet SSH input exceeds the command byte limit", code="invalid_command")
        if stdout_consumer is not None and not callable(stdout_consumer):
            raise SessionError("stdout_consumer must be callable", code="invalid_consumer")
        seconds, idle, budget, pages = _fortinet_limits(
            *(default if override is None else override for default, override in zip(
                self._limits, (timeout_seconds, idle_timeout_seconds, capture_max_bytes, max_pages)
            ))
        )
        if not self._command_lock.acquire(blocking=False):
            raise SessionError("Fortinet SSH already has a command in progress", code="busy")
        try:
            started = ssh_module._moment(self._timestamp)
            deadline = time.monotonic() + seconds
            output = _FortinetOutput(self._prompt_pattern, command=data, previous=self._last_prompt,
                                     consumer=stdout_consumer, allow_continuation=self._platform == "fortios",
                                     exact_prompt=self._expected_prompt(command))
            self._write_input(data + b"\n", deadline)
            match = self._read_output(output, deadline, idle, budget, pages)
            if match is not None:
                self._accept_prompt(match)
            else:
                self._last_prompt = b"> "
            finished = max(started, ssh_module._moment(self._timestamp))
            refusal = "device_cli_error" if output.refused else None
            status = 1 if refusal else 2 if match is None else 0
            return FortinetResult(status, bytes(output.output), "", started, finished,
                                  context=self.context, continuation=match is None, refusal=refusal)
        except BaseException:
            self.close()
            raise
        finally:
            self._command_lock.release()


def fortinet_session(device, credential, *, address=None, port=None, login=None,
                     connect_timeout_seconds=FORTINET_LOGIN_SECONDS,
                     timeout_seconds=ssh_module.DEFAULT_TIMEOUT_SECONDS,
                     idle_timeout_seconds=FORTINET_IDLE_SECONDS,
                     capture_max_bytes=ssh_module.CAPTURE_MAX_BYTES,
                     max_pages=FORTINET_MAX_PAGES) -> _FortinetSession:
    """Open one pinned, interactive Fortinet SSH connection for sequential commands."""
    try:
        platform = platforms.normalize(getattr(device, "platform", None))
    except platforms.PlatformError:
        platform = None
    if platform not in ("fortios", "fortiadc"):
        raise SessionError("fortinet_session requires a FortiOS or FortiADC target", code="invalid_platform")
    target_address = getattr(device, "address", None) if address is None else address
    target_port = getattr(device, "port", None) if port is None else port
    key_line = hostkey.pinned_line(target_address, target_port, getattr(device, "host_key_fingerprint", None),
                                  getattr(device, "host_key", None))
    limits = _fortinet_limits(timeout_seconds, idle_timeout_seconds, capture_max_bytes, max_pages)
    return _FortinetSession(platform, target_address, target_port, login, credential, key_line,
                            getattr(device, "legacy_ssh", None), limits, connect_timeout_seconds)
