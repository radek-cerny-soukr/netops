# SFTP transport

`netops_core.sftp` asks one device for the metadata of one remote path through the OpenSSH `sftp`
client and returns what it could parse. Like [`ssh.py`](ssh.md) it is a transport: it does not
retry, does not keep a session open, does not read a file body, and never falls back to a weaker
setting when something fails.

## Why this lives in the core and not in a component

Two components of the family need SFTP in the production path, and they need the same client with the
same hardening:

- the **helper** reads metadata of an enrolled path (`sftp_stat`), read-only;
- the planned **admin** replaces a configuration file atomically, which is a `put` of one file.

A transport used by two components is a core concern, exactly like the exec channel. Putting it here
also means there is one place where the client call, the credential handling and the workspace are
written down, and one place the tests hold against.

## The client call

| Constant | Value |
|---|---|
| `SFTP_BINARY` | `sftp` |
| `CONFIG_FILE` | `/dev/null`, passed as `-F` before anything else |
| `DEFAULT_TIMEOUT_SECONDS` | `60.0` |
| `LIST_COMMAND` | `ls -ln "<path>"`, a batch of exactly one line |
| `LISTING_MAX_BYTES` | `262144`; a larger answer is refused unparsed |

The argument vector is built by `argv()` and is the one of `ssh.py` with three differences: the
binary, `-P` instead of `-p` for the port, and no remote command at the end. Everything else is
shared code, not a copy: the hardening options come from `ssh.OPTIONS` / `ssh.PASSWORD_OPTIONS`, the
options of a legacy profile are appended **after** them, `UserKnownHostsFile` points inside the
workspace of this one call, and the workspace, the askpass script and the identity file are prepared
by `ssh._prepared`. There is no `ControlMaster` and no `ControlPath`.

## The batch goes on standard input, and why

**Measured on 17 September 2026** with OpenSSH 9.2p1, by running `/usr/bin/sftp` with `-S` pointing
at a script that writes its own argument vector to a file. `sftp` is a facade: it builds an `ssh`
command line and runs it. With `-b`:

```
-oForwardX11 no
-oPermitLocalCommand no
-oClearAllForwardings yes
-F
/dev/null
-o
BatchMode=no
-o
StrictHostKeyChecking=yes
-obatchmode yes          <- added by sftp because of -b
-oForwardAgent no
-oPort 22
-l
user
-s
--
192.0.2.20
sftp
```

Without `-b` the line `-obatchmode yes` is absent and nothing else changes.

`BatchMode=yes` disables the askpass program, which is how a password reaches the client
([`ssh.md`](ssh.md)). So `-b` is not used at all and the single command is written to the standard
input of `sftp`, which reads its commands from there when it is not attached to a terminal. That the
option happens to be appended *after* ours - and `ssh` keeps the first value it is given, measured in
the same session with `ssh -G` - is not relied on: the password path must not depend on the order in
which a facade appends an option.

A consequence of not using `-b` is that `sftp` echoes each command it reads to standard output as
`sftp> <command>`, and that it does **not** end with a non-zero exit status when the command itself
fails. Both are handled below.

## What comes back

OpenSSH `sftp` has no `stat` command, so the batch is `ls -ln <path>` in double quotes: `-l` for the
long form, `-n` for numeric owner and group, so no name from the device's user database is printed or
resolved. Measured against a server that speaks SFTP version 3, the answers look like this (`rc` is
the exit status of `sftp`, not of the command):

```
# a file                                          rc 0
sftp> ls -ln "/safe/log"
-rw-r--r--    ? 0        0            1234 Sep 10 02:26 /safe/log

# a directory: sftp lists the content, with full paths          rc 0
sftp> ls -ln "/safe/dir"
-rw-------    ? 0        0              11 Sep 10 02:26 /safe/dir/a.conf
-rw-------    ? 0        0              22 Sep 10 02:26 /safe/dir/b.conf
drwx------    ? 0        0            4096 Sep 10 02:26 /safe/dir/sub

# an empty directory                              rc 0, nothing on stderr but the progress line
sftp> ls -ln "/safe/empty"

# a path that is not there                        rc 0
sftp> ls -ln "/safe/missing"
[stderr] Can't ls: "/safe/missing" not found
```

The link count is always `?` because SFTP version 3 carries no link count. Standard error always
carries the client's own progress line `Connected to <host>.`, on success as well.

`Entry` is a frozen dataclass: `kind`, `mode`, `size`, `modified_ls`, `name`, `entry_count`, `said`,
`started_at`, `finished_at`.

| Field | What it is |
|---|---|
| `kind` | from the first character of the permission string: `-` is `file`, `d` is `directory`, `l` is `symlink`, anything else is `other` |
| `mode` | the permission string translated into permission bits, `setuid`, `setgid` and the sticky bit included |
| `size` | the size column, an integer |
| `modified_ls` | **the timestamp as `ls` printed it**, verbatim - see below |
| `name` | the path the listing line ended with, only for a single entry that is the requested path |
| `entry_count` | for a directory: how many lines the listing had; never the names |

**`modified_ls` is not a modification time.** It is the precision of `ls`: `Sep 10 02:26` for a
recent file and `Sep 10  2024` for an older one, in the time zone of the client, with no year in the
first form and no minute in the second. The field is named after what it is, so nobody computes with
it. A real `mtime` needs a protocol-level `stat`, which this client does not expose.

## Telling a file from a directory

`sftp` has no `ls -d`, so a directory is answered with its content. The rule is:

- one listing line whose name is exactly the requested path -> that path itself, `kind` from its
  type character;
- anything else -> `kind` is `directory` and only `entry_count` is filled in. **The names of the
  entries are never returned**, not in a field and not in a message. A directory holding one entry is
  still a directory, because the entry's name is not the requested path.
- no listing line and nothing on standard error but the progress line -> an empty directory,
  `entry_count` 0.
- no listing line and something else on standard error -> a refusal carrying what the client said.
  That last rule is what turns `Can't ls: ... not found` into an error, because the exit status does
  not: measured above, `sftp` ended with 0 on a path that is not there.

## The path

The batch is line-oriented and the path is quoted in it, so the path is checked before it is written:
absolute, at most 2000 characters, no `..` component, no `"`, no newline, no carriage return, no NUL,
and no leading or trailing whitespace. A caller that has its own allowlist - the helper checks the
path against the enrolled roots first - runs both checks, in that order.

Inside the double quotes the client does **not** expand a glob: measured, `ls -ln "/safe/*"` asked the
server for the literal name `/safe/*` and answered `Can't ls: "/safe/\*" not found`. So a path with
`*`, `?` or `[` is one path, not a pattern.

## Refusals

| Situation | Refusal |
|---|---|
| a path the batch line could not carry | `SftpError` naming the rule |
| credential of another kind | `SftpError` naming the kind |
| the client does not finish in `timeout_seconds` | `SftpError` naming the host and the timeout |
| any exit status other than 0 | `SftpError` carrying the status and what the client said |
| exit status other than 0, no `legacy_ssh` profile, and the client mentions a failed negotiation | the same remedy text as `ssh.run_command`: the exception is written per device as `legacy_ssh` |
| an empty listing with a complaint on standard error | `SftpError` carrying the complaint |
| a listing larger than `LISTING_MAX_BYTES` | `SftpError`; the answer is not parsed at all |
| a single listing line this parser does not know | `SftpError`; nothing is guessed |

`SftpError` is `ssh.SshError`: one transport, one refusal type.

## The legacy remedy, and when it cannot appear

`sftp` is a facade over `ssh`, so a device that offers only `ssh-rsa` fails the same way and the same
remedy is produced from `ssh.NEGOTIATION_MARKER` and `ssh.LEGACY_REMEDY`.

But a **measured fact from 13 September 2026** limits it: against an old switch the device closed the
connection before the client had evaluated the offer. Then standard error carries no `no matching`
marker, and all that is left is the generic failure - `Connection closed by <host> port 22`, exit
status 255, no algorithm named. What an operator sees is an opaque connection failure, and the fix is
the same one: name `legacy_ssh` for that one device in its inventory entry. `ssh_read` against the
same device usually names it explicitly, so the exec channel is the better place to ask.

## Testing it

`stat()` takes the runner as an argument (`run=`, by default the subprocess runner), so the tests pass
a recorder that returns a `subprocess.CompletedProcess` and assert on the exact argument vector, the
environment, the bytes of the batch, and the parsed answer: `-F /dev/null` first, the hardening
options in order, the legacy options behind them, no `-b`, a batch of exactly one line, the password
absent from both the argument vector and the environment values, mode 0600 on the identity file, the
workspace gone after success and after failure, a directory answered with a count and no name, and the
listing cap refusing before the parse. The listing samples in `tests/test_sftp.py` are the bytes
recorded from the real client above.
