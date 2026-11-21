"""Compatibility with Admin dialogs that need more than Core's command result."""
from dataclasses import dataclass
import re
from time import monotonic

from netops_core.session import (
    FORTINET_COMMAND_MAX_BYTES, SessionError, _FortinetOutput, _fortinet_prompt,
)


PASSWORD = re.compile(rb"(?i)[ \t]*(?:Please enter current administrator )?password:[ \t]*\r?\Z")


@dataclass(frozen=True)
class Reply:
    rc: int
    stdout: bytes
    context: str | None
    continuation: bool
    password: bool


class _DialogOutput(_FortinetOutput):
    # Core intentionally discards CLI error bodies. Admin needs exact absence
    # markers and the full answer for its restricted account and write checks.
    def __init__(self, *args, password=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.ask_password = password

    def password(self):
        return self.ask_password and self.line_head and self.erase is None and PASSWORD.fullmatch(self.pending) is not None

    def continuation(self):
        return self.password() or super().continuation()


def dialog(shell, command, seconds, *, typed=None, password=False, capture_max_bytes=None, sent=None):
    """Use the open Core PTY and its frame reader for an Admin CLI dialog. `sent` is called once the line has been
    written to the session, before the device answers (1.0.12 G24: a profile batch step starts only then)."""
    shell._alive()
    wire = command if typed is None else typed(command)
    if any(mark in wire for mark in ("\n", "\r", "\0")):
        raise SessionError("Fortinet SSH input must be a single line", code="invalid_command")
    data = wire.encode("utf-8")
    if len(data) > FORTINET_COMMAND_MAX_BYTES:
        raise SessionError("Fortinet SSH input exceeds the command byte limit", code="invalid_command")
    if not shell._command_lock.acquire(blocking=False):
        raise SessionError("Fortinet SSH already has a command in progress", code="busy")
    try:
        deadline = monotonic() + seconds
        budget = shell._limits[2] if capture_max_bytes is None else capture_max_bytes
        output = _DialogOutput(shell._prompt_pattern, command=command.encode("utf-8"),
                               previous=shell._last_prompt, allow_continuation=shell._platform == "fortios",
                               exact_prompt=shell._expected_prompt(command, navigate=False if password else None),
                               keep_refusal=True, password=password)
        shell._write_input(data + b"\n", deadline)
        if sent is not None:
            sent()
        match = shell._read_output(output, deadline, seconds, budget, shell._limits[3])
        asked = output.password()
        if match is not None:
            shell._accept_prompt(match)
        else:
            shell._last_prompt = output.pending
        incomplete = match is None and not asked
        return Reply(1 if output.refused else 2 if incomplete else 0, bytes(output.output),
                     shell.context, incomplete, asked)
    except BaseException:
        shell.close()
        raise
    finally:
        shell._command_lock.release()


def has_hostname(shell, hostname):
    return _fortinet_prompt(shell._platform, hostname).fullmatch(shell._last_prompt) is not None
