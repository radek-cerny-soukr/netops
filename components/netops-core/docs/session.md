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
| `close()` | closes the terminal, waits for the client, kills it when it ignores the hangup, removes the workspace |

`expect` matches the earliest pattern in the stream, not the first in the list, so `[b"ruckus> ",
b"Please login"]` tells a successful login from a repeated prompt by the returned index. The session
keeps only the bytes it has read but not yet handed out; what `expect` returned is forgotten.

A timeout bounds how long `expect` waits, and `capture_max_bytes` bounds how much it holds while it
waits. A device that answers a prompt with an endless stream - or with a stream that simply never
carries the awaited pattern - is stopped at that budget with a `SessionError` instead of growing the
buffer until the deadline. The budget applies to what is held at one time, so it is not a limit on
the length of a session: bytes handed out by a match no longer count against it. `close()` kills the
client as usual, so nothing keeps writing after the refusal.

## What never leaves the session

A `SessionError` names the host, the number of patterns awaited, the seconds waited or the budget
that was exceeded, and the number of bytes seen - never the bytes. Devices that ask for the password inside the shell echo it on the
terminal, so the transcript of a login phase is a secret: the library refuses to put it in an error,
and the caller is expected to drop it (`discard`) rather than log it. Tests hold the library to that:
a timeout error containing the buffer is a failing test.

## Measured against

Recorded 16 September 2026 with this code, one device per platform, from a host with OpenSSH 9.2:

| device | authentication | `legacy_ssh` | result |
|---|---|---|---|
| Ruckus Unleashed access point (Dropbear, offers only `ssh-rsa`) | password, asked for again inside the shell | `rsa-sha1` | `Please login:` answered, `Password` answered, prompt `ruckus>` reached, `enable`, `show sysinfo` returned 724 bytes; the login phase (104 bytes) was discarded |

The prompt for the second password is the word `Password`, not `password :` as older notes on that
platform say - match on `assword` and read the index, not on an exact prompt.
