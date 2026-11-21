# Interactive session

`netops_core.session` is the second transport mode: one OpenSSH client process on a pseudo-terminal,
driven by the caller with `expect` and `send`. It exists for devices that have no exec channel - an
access point running Dropbear answers `ssh host command` with `Invalid argument` - and for devices
that authenticate again inside their shell after the SSH login. Everything that `ssh.py` fixes stays
fixed here: the same options, the same workspace, the same handling of a key or a password. The only
additions are `-tt`, which asks for a terminal, and the fact that the process lives until `close()`.

## Opening

```
Session(host, port, login, credential, host_key_line, *,
        legacy_ssh=None, timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
        capture_max_bytes=CAPTURE_MAX_BYTES, spawn=None, now=None)
```

The arguments are those of `ssh.run_command` without a command. The client is forked on a
pseudo-terminal (`pty`) and replaced with the OpenSSH binary (`execvpe`), so it sees a terminal and behaves as it would for a person; the
environment is the one `ssh.py` builds, nothing inherited. A session is a context manager, and
`__exit__` calls `close()` whatever happened inside the block.

## Reading and writing

| call | what it does |
|---|---|
| `expect(patterns, timeout_seconds)` | reads until one of the byte patterns appears, returns `(index, data)` - the index of the earliest matching pattern and the bytes consumed up to and including the match; raises `SessionError` when the timeout passes or the process ends first |
| `send(line)` | writes `line` and a newline; a line that carries `\n`, `\r` or `\x00` is refused |
| `discard(data)` | counts bytes the caller has decided not to keep; the count is `discarded_login_bytes` |
| `close()` | closes the terminal, waits for the client, ends it when it ignores the hangup - the whole terminal group, not only the client - removes the workspace |

`expect` matches the earliest pattern in the stream, not the first in the list, so `[b"ruckus> ",
b"Please login"]` tells a successful login from a repeated prompt by the returned index. The session
keeps only the bytes it has read but not yet handed out; what `expect` returned is forgotten.

A timeout bounds how long `expect` waits, and `capture_max_bytes` bounds how much it holds while it
waits. A device that answers a prompt with an endless stream - or with a stream that simply never
carries the awaited pattern - is stopped at that budget with a `SessionError` instead of growing the
buffer until the deadline. The budget applies to what is held at one time, so it is not a limit on
the length of a session: bytes handed out by a match no longer count against it. `close()` ends the
client as usual, so nothing keeps writing after the refusal.

## Closing bounds the same way

Closing the terminal hangs the client up. If it is still there after that, `close()` asks it to end,
then signals the whole group the pseudo-terminal gave it - the session the client leads and nothing
else - and finally kills and reaps, so a process the device's shell started cannot outlive the
session that owned it and nothing is left as a zombie. That sweep of the group happens whether the
client had to be killed or ended by itself on the hangup. This is the cleanup `ssh.py` uses for a
single command, on the transport that stays open (`docs/ssh.md`).

## What never leaves the session

A `SessionError` names the host, the number of patterns awaited, the seconds waited or the budget
that was exceeded, and the number of bytes seen - never the bytes. Devices that ask for the password inside the shell echo it on the
terminal, so the transcript of a login phase is a secret: the library refuses to put it in an error,
and the caller is expected to drop it (`discard`) rather than log it. Tests hold the library to that:
a timeout error containing the buffer is a failing test.

A `SessionError` carries no text of the device at all, so there is nothing here to forward by
accident. The rule that governs `said` on the other transport - the other side's text is for an
operator reading it by hand and is never put into a report, a log line or a prompt on its own -
holds for anything a caller keeps out of a transcript itself (`docs/ssh.md`).

## Platform contract

Ruckus Unleashed uses an interactive session and may request a second password inside the shell. The session discards authentication-phase transcript data and returns only the selected command answer. Password-prompt handling matches the documented `assword` suffix and prompt index rather than assuming one capitalization or exact surrounding punctuation. The credential's device privileges remain governed by the component's explicit role boundary; a console prompt does not establish a read-only account.

## Fortinet command series

```python
from netops_core.session import fortinet_session

with fortinet_session(device, credential) as cli:
    status = cli.run("get system status")
    if status.rc == 0:
        configuration = cli.run("show", stdout_consumer=bounded_consumer)
```

The factory accepts an inventory `Device` or an object with `platform`, `address`,
`port`, `host_key`, `host_key_fingerprint` and optional `legacy_ssh` attributes.
Pass the resolved vault credential. The optional `address`, `port` and `login`
override the endpoint and the credential's login. The connection uses the
[enrollment pin](ssh.md#fortinet-host-key-from-enrollment) and one `ssh -tt`.

`run` returns `FortinetResult` with `rc=0` for a completed response, `rc=1`
with `refusal="device_cli_error"` for a recognized CLI refusal, and `rc=2` with
`continuation=True` for the FortiOS `> ` prompt. Supply the next line with `run`
or close the session. `context` is the parenthesized CLI context or `None`,
also available on the session after login. Check context and product identity
where the operation requires them. The CLI status is assigned by Core.

`stdout` is a byte string with the command echo, pager and final prompt removed,
and terminal CRLF normalized to LF. `stderr` and `said` are empty. An optional
synchronous `stdout_consumer` receives bounded byte chunks and leaves `stdout`
empty. Send the bytes to the caller's redactor or bounded consumer. Treat
streamed bytes as provisional until `rc=0` and discard them on an exception
or refusal. A CLI refusal withholds its text from the result.

Login waits up to `connect_timeout_seconds` (20). Each `run` defaults to
`timeout_seconds` (120), `idle_timeout_seconds` (15), `capture_max_bytes`
(16 MiB including terminal framing) and `max_pages` (128). Set defaults on the
factory or override them per command. A pager receives one space per page.
The prompt must start a new line and match the prompt of the current context
exactly. Commands that navigate may change its context while keeping the login
prompt's identity and ending. Core sends an empty line at a candidate prompt
and accepts the response once two identical prompts delimit the empty reply.
A prompt-shaped line followed by more output stays in the response. Continuation
and password prompts are handled without sending an empty line.

Before login, OpenSSH diagnostics distinguish `auth`, `host_key`, `negotiation`
and `disconnected`. Limits or loss of framing raise a coded `SessionError` and close the session.
Pin problems raise `HostKeyError` before opening. Consumer failure raises
`OutputConsumerError` or `OutputLimitError` and closes the session.
