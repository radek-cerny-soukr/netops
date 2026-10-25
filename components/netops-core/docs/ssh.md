# SSH transport

`netops_core.ssh` runs one command on one device through the OpenSSH client and returns what the
device wrote. It is a transport: it does not parse output, does not retry, does not keep a session
open, and never falls back to a weaker setting when something fails.

## The client call

| Constant | Value |
|---|---|
| `SSH_BINARY` | `ssh` |
| `CONFIG_FILE` | `/dev/null`, passed as `-F` before anything else, so no user or system client configuration is read |
| `DEFAULT_TIMEOUT_SECONDS` | `120.0` |
| `CAPTURE_MAX_BYTES` | `16777216`; the most a call will hold from standard output before it stops the client |
| `STDERR_MAX_BYTES` | `65536`; the head of standard error that is kept, the rest is read and dropped |
| `OPTIONS` | `BatchMode=yes`, `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`, `ClearAllForwardings=yes`, `ProxyCommand=none`, `PermitLocalCommand=no`, `ControlMaster=no`, `ControlPath=none` |

The options are built per authentication kind. A key uses `BatchMode=yes`. A password cannot:
`BatchMode=yes` disables the askpass program, so password authentication uses `BatchMode=no` plus
`PreferredAuthentications=password`, `KbdInteractiveAuthentication=no`,
`NumberOfPasswordPrompts=1` and `PubkeyAuthentication=no`. This permits one password attempt
and no fallback to another method. A server offering only keyboard-interactive is refused
without sending the password. The same options apply to command, terminal and SFTP transports.

`UserKnownHostsFile` points at a file inside the workspace of this one call, written from the host key
line the caller passes in, and `GlobalKnownHostsFile=/dev/null` follows it, so the host's own
`/etc/ssh/ssh_known_hosts` is never read beside the pin. Trust comes from the pin in the inventory,
never from a file on the host that runs the command. `known_hosts_options()` in this module builds the pair,
and the `argv()` of the `sftp` and `session` modules takes it from here. The options of a legacy profile (`legacy_ssh.openssh_options`) are appended
**after** the base options, so an exception widens the algorithm list and cannot replace the hardening.

## Authentication

`run_command` takes a `vault.Credential` of kind `password` or `ssh-key`. Any other kind is refused
with `SshError` naming the credential kind and the two that can be used.

| Kind | What happens |
|---|---|
| `ssh-key` | the private key is written into the workspace with `O_EXCL` and mode 0600 and passed as `-i` |
| `password` | the password is written into `<workspace>/secret` with mode 0600, an askpass program reads that file, and the environment carries `SSH_ASKPASS`, `SSH_ASKPASS_REQUIRE=force`, `DISPLAY=none`, and `NETOPS_ASKPASS_FILE` with the path of the secret |

### Where the askpass program comes from

The client executes the askpass program, so that program must reside on a filesystem that permits execution. By default `<workspace>/askpass` is written with mode 0700 next to the secret. If the temporary filesystem is mounted `noexec`, executing that script fails with `EACCES`; `noexec` does not prevent reading a file stored there. A separately installed program on an executable filesystem can read the private secret in that workspace.

A deployment that mounts its temporary directory `noexec` therefore ships the program elsewhere and
names it in `NETOPS_ASKPASS_PROGRAM`. The NetOps image does this: it installs `netops_core/askpass.py`
as `/usr/local/bin/netops-askpass`, owned by root with mode 0755, and sets the variable to that path.
The module file `netops_core/askpass.py` inside `site-packages` is **not** a substitute, because package
files are installed without the execute bit and the check below refuses it. The named program must be a regular file,
executable by this process, and not writable by group or other, because it is the program the
password is handed to. The secret itself stays in the workspace either way.

Both paths are checked before the client is started, so a deployment where the password could not be
handed over is refused with a message naming the reason and the variable, instead of failing later
as an authentication error that looks like a wrong password.

The installed `netops-askpass` prints the file named in `NETOPS_ASKPASS_FILE` only when it is a
regular file of at most 1 MiB, opened without blocking. Without the variable, or with a file it
cannot read, it writes one line `netops-askpass: <reason>` to stderr - the reason, never the content
- and exits with `1`, which the client takes as a refused prompt.

The password is never an argument and never a value in the environment of the `ssh` process: only the
path of the file that holds it is. The environment is built from nothing and is exactly `PATH`,
`HOME` (the workspace), `LC_ALL=C`, plus the askpass variables for a password.

## Bounded receive

The answer of a device is attacker-controlled in its length as well as in its content, so the call
does not hand the client an open bucket. The default runner starts the client itself, reads standard
output and standard error as they arrive, and holds at most `capture_max_bytes` of standard output.
A device that keeps sending past that budget - deliberately, or through a command that never ends -
is killed and the call is refused with `SshError`; nothing of what it sent is returned. Standard
error keeps only its first `STDERR_MAX_BYTES` and the rest is read and dropped, so a noisy client
cannot grow memory either and cannot block by filling its pipe.

### One deadline, and what is stopped when it passes

`timeout_seconds` becomes one monotonic deadline, taken before the client is handed anything, and it
holds until the process has really ended: while the streams are read, and for the final wait after
they have closed. A client that closes standard output and standard error and then keeps running is
refused at that deadline like any other; going quiet buys it no time. A client that keeps its streams
open and says nothing is refused at the same deadline, as it always was.

The client is started in its own session, so it leads a process group, and it is owned from the
moment it is started rather than from the moment the first byte arrives. Every way out - the
deadline, the budget, a failure to set the reading up, an error inside the reading loop - leaves
through one cleanup: terminate, a short grace, then kill, sent to the group as well as to the
client, and what was killed is reaped.

A call that finished on its own is swept the same way, only without a refusal: once the client has
been reaped, whatever is left of its group is asked to end, given the same short grace and then
killed. So a client that exits with a status of its own while a process it started keeps running -
`sftp` runs its own `ssh` - does not leave that process behind as an orphan, and no zombie is left
either. Nothing of the answer changes: the status, the output and the moments of the call are the
ones the client produced, and when the group is already empty, which is the ordinary case, the sweep
is a single system call. The interactive session closes the same way (`docs/session.md`).

The reading does not wait for the streams to close once the client itself has ended. A process the
client started inherits its standard output and standard error, and as long as it holds them they
never reach end of file - `sleep 30 &` in a shell, or the `ssh` that `sftp` runs. The runner watches
the client through a process file descriptor (`os.pidfd_open`): when the client has ended, what is
already waiting in the two pipes is read, without waiting for more, and the reading stops; the client
is reaped and its group is swept as above. So such a process neither turns a finished call into a
timeout nor adds anything it writes later to the answer. Where a process file descriptor cannot be
opened, the reading falls back to waiting for end of file under the same deadline.

`capture_max_bytes` defaults to `CAPTURE_MAX_BYTES`, which is the budget of a configuration-sized
answer, not of a diagnostic one. A caller that knows it asks for little passes a smaller number, and
a caller that reads a whole configuration keeps the default; the helper additionally refuses an
answer over its own two-megabyte limit after decoding, which is a decision about what a diagnostic
may return, not a memory bound.

The `run=` argument stays the seam the tests use: when a caller passes its own runner, that runner
decides what it reads and the budget is the caller's business. Only the default path - the one every
component uses in production - is the capped one.

### The host key scan is bounded the same way

The known hosts line handed to `UserKnownHostsFile` above comes from `netops_core.hostkey.scan`,
which runs `ssh-keyscan` against the device and keeps the line whose fingerprint matches the pin
from the inventory - there is no first contact trust, so a device that offers no matching key is
refused. That scan happens before any credential is used, but its answer is exactly as
attacker-controlled as a command's: a device, or anything sitting in front of it, can hold the
connection open and keep writing. The host key scan takes the same `capture_max_bytes` seam and
defaults to the same capped runner as `run_command`, sized with its own constant,
`KEYSCAN_CAPTURE_MAX_BYTES` (`262144`), since a
host key answer is a handful of lines, never a configuration. A peer that keeps sending past that
budget is killed and the scan is refused with `HostKeyError`, which is not a subclass of `SshError`;
the `run=` argument stays the seam the tests use.

The scan requests one host-key type at a time — `ed25519`, then `ecdsa`, then `rsa` — with `ssh-keyscan -t`, and stops at the pinned key. Asking for multiple types at once opens multiple connections and can exceed a device's terminal-session limit. Sequential requests bound that load to one connection at a time.

`ssh-keyscan` exits 1 when a requested type is unavailable. An answer containing only comment lines does not establish a key, whether the client writes those comments to standard output or standard error. An empty or comment-only answer advances to the next type; an answer with a key line and a nonzero status is refused. OpenSSH 10.0p2 and 9.2p1 differ in where they write the comment, so parsing is based on a non-comment key line rather than comment placement. Attempts share one timeout: later attempts receive only the remaining time and none starts with less than one second.

For a device whose inventory entry carries `legacy_ssh: "rsa-sha1-dh14"` the scan cannot use
`ssh-keyscan`, which offers no SHA-1 key exchange and has no option to add one. `scan(...,
legacy="rsa-sha1-dh14")` instead runs one `ssh` with every authentication method switched off, the
login `netops-hostkey`, `StrictHostKeyChecking=accept-new` into a known-hosts file inside a private
temporary directory, and the profile's options; the connection ends at authentication, the file then
holds the key the device offered, and the same pin comparison decides. The directory is removed before
the scan returns. IOSv 15.9(3)M12 and IOSvL2 15.2 profiles can require `ssh-rsa` with `diffie-hellman-group14-sha1`; the explicitly selected legacy profile does not change the pinned-key comparison.

## The workspace

Every call creates its own directory with `tempfile.mkdtemp(prefix="netops-core-")` and mode 0700.
Before anything else is written into it, the call creates an empty owner file with `O_EXCL` and mode
0600, takes an exclusive `flock` on it and only then renames it to `.owner`, so that name never
stands for a file that is not locked yet; the descriptor is not inherited by the client. The
directory then holds the `known_hosts` file, and the identity or the secret and the askpass script.
It is removed in a `finally` block, so it is gone after the call whether the command succeeded,
failed, timed out, or raised; the lock is released only after the removal.
The paths of the `known_hosts` file and of the identity reach the client inside its options, and
OpenSSH rewrites such a path before it opens it: it expands `%` tokens (`%h` is the host) and
`${VARIABLE}` in `UserKnownHostsFile` and in an identity given with `-i`, splits `UserKnownHostsFile`
on whitespace into several files, and reads quotes and backslashes in an option value. `-i` cannot even
be escaped: the client checks the literal path before it expands it. So `argv()` of this module, of
`sftp` and of `session`, `known_hosts_options()` and the legacy host key probe refuse a path that holds
`%`, `$`, a quote, a backslash, whitespace or a control character with `SshError` (`HostKeyError` for
the probe) naming the path and `TMPDIR`; such a path can only come from the temporary directory, and
the call is refused before the client is started instead of reading a different file than the one the
workspace holds. `netops_core.sftp.stat` and `netops_core.session.Session` create, lock and remove their workspaces
through the same functions. A session holds its lock from opening until `close()` has removed its
directory, so the workspace of an open session - or of one that is never closed, until its process
ends - counts as running.

### What a killed call leaves behind

A `finally` block does not run when the process ends on a signal it cannot catch or does not handle -
`SIGKILL`, or `SIGTERM` without a handler - or when the host stops. The directory then stays behind
with everything written so far: once the credential has been handed over, the password in `secret` or
the private key in `identity`, each with mode 0600, readable by the user of the process. A client
started by `run_command` or `netops_core.sftp.stat` runs in its own session and is not stopped with
it; the client of a session loses its terminal.

The kernel releases the lock of a process that has ended. So every later `run_command`,
`netops_core.sftp.stat` or `netops_core.session.Session` of the same user with the same temporary
directory first removes what such a call left: it looks only at the entries directly in
`tempfile.gettempdir()` whose names start with `netops-core-`, and removes one only when `lstat`
shows a directory, not a symbolic link, owned by that user with mode 0700, whose `.owner` opens
without following a symbolic link as a regular file of that user, and whose lock can be taken at
once. A directory whose lock is held belongs to a call that is still running and is left alone. A
directory without `.owner` is never removed this way - one written by a call that has not taken
its lock yet; what an ended process left there has to be removed by hand. A
failure of this cleanup never fails the call.

Nothing is removed before that next call. A remainder therefore lasts until a later call of the same
user, until the temporary directory is cleared, or, in the NetOps container, where `/tmp` is a
`tmpfs`, at the latest until the container stops.

## Result and refusals

`Result` is a frozen dataclass: `rc`, `stdout` (raw bytes; the caller decodes), `said`, `started_at`,
`finished_at`. The two moments are UTC in `%Y-%m-%dT%H:%M:%SZ`. `said` is the standard error of the
client decoded with `errors="replace"`, stripped of control characters and cut to 200 characters, so a
device that writes a banner or an escape sequence cannot reshape a log line.

### The message of a failure names a reason, not the device's words

Standard error is written by the other side. A device, or anything that can write into its banner or
its command output, can put text there - including a secret it holds, or a sentence addressed to
whoever reads the error. So the **message** of an `SshError` never repeats it. It names the host, the
exit status and one reason out of the closed list `REASONS` of this module, matched by marker;
anything unmatched is `UNKNOWN_REASON`, which says the client failed for a reason this transport does
not recognize. The raw text stays on the exception, and on a `Result`, as `said`.

`said` is the other side's own text: unanonymized, attacker-controlled, possibly a secret the device
holds, possibly a sentence written to be read by whoever reads the error. It is there for one
purpose, an operator diagnosing a device by hand. It must not be forwarded automatically - not into
a report, not into a log line, not into a prompt handed to a model, not into an audit record that is
read back by anything but a person. A caller that passes an error on to any of those passes the
classified sentence, which is this module's own text.

This is why the legacy remedy works the way it does: it is a fixed sentence of this module, triggered
by a marker in `said`, not an echo of what the device wrote.

The exit status separates two different events. The OpenSSH client reports its own failure - it could
not connect, could not authenticate, could not negotiate - as 255 (`CLIENT_FAILURE_CODE`); every other
code is the status the remote command itself ended with. So 255 and a timeout are refusals, and any
other code is a `Result` carrying `rc` and everything the command wrote. A negative status is not a
code at all: it is how a client ended by a signal is reported (`-9` after `SIGKILL`, for example by the
out-of-memory killer), and what such a client wrote is cut off wherever the signal found it. It is a
failure of the client like 255, refused with `SshError` whose `rc` is the negative status and whose
message names the signal; nothing it wrote is returned. The transport does not judge
a command's own status: whether a non-zero `rc` is an error is a decision of the caller, who knows
what it asked for. The auditor refuses a snapshot unless `rc` is 0; the helper returns the output and
reports `rc`.

| Situation | Refusal |
|---|---|
| credential of another kind | `SshError` naming the kind |
| the askpass program cannot be executed, or `NETOPS_ASKPASS_PROGRAM` names something that is not an executable regular file, or one that group or other may write | `SshError` naming the variable and the reason, before the client starts |
| the client does not finish in `timeout_seconds` | `SshError` naming the host and the timeout; the client and the group it leads are stopped and reaped first |
| the client writes more than `capture_max_bytes` on standard output | `SshError` naming the budget; the client and the group it leads are stopped and no partial answer is returned |
| `capture_max_bytes` is not a whole number of at least 1 | `SshError` naming the value |
| the path of the known hosts file or of the identity holds `%`, `$`, a quote, a backslash, whitespace or a control character (a `TMPDIR` the client would rewrite) | `SshError` naming the path and `TMPDIR`, before the client starts |
| exit status 255, or a status that is not a whole number | `SshError` carrying `rc` and `said`, whose message names a reason from `REASONS` and not the client's words |
| a negative status: the client was ended by a signal | `SshError` carrying the negative `rc` and `said`, whose message names the signal; the partial output is not returned |
| exit status 255, no `legacy_ssh` profile, and `said` mentions a failed negotiation | `SshError` with the remedy: the exception is written per device as `legacy_ssh`, the profile list is closed, and there is no global switch |

The remedy appears only when no profile was named. A device that already carries an exception and
still fails to negotiate gets the plain failure, because the exception it has is not the answer.

## Testing it

`run_command` takes the runner as an argument (`run=`, by default the subprocess runner), so the tests pass a recorder
that returns a `subprocess.CompletedProcess` and assert on the exact argument vector and environment:
`-F /dev/null` first, the hardening options in order, `UserKnownHostsFile` inside the workspace
followed by `GlobalKnownHostsFile=/dev/null` (checked once more by `ssh -G` over the built vector), the
legacy options after the base ones, the password absent from both the argument vector and the
environment values, mode 0600 on the identity file, the workspace removed after success and after
failure, and the remedy text present only without a profile.

`tests/test_abandoned_workspaces.py` kills a call in a child process with `SIGKILL` after it has
written the password and checks that the next call removes what it left, that the directory of a
call that is still running stays, and that a symbolic link, a directory of another mode, a directory
without an owner file and one whose `.owner` is a symbolic link are left alone. The same two checks
run for `netops_core.sftp.stat` and for an open `netops_core.session.Session`, and no workspace or
open descriptor outlives a finished or refused call of any of the three.

## Platform contracts

Host-key algorithms, authentication methods and permitted legacy profiles are platform-specific. FortiOS, ExtremeXOS, Arista EOS, Cisco IOS/IOS-XE and Junos retain their exact documented version and account boundaries; transport support does not authorize device changes. Select a legacy profile only for the exact device that requires it. Ruckus Unleashed uses the documented [interactive session](session.md) path instead of an exec channel.

Exit status 255 is a transport refusal. Other command statuses remain a `Result` with their output, rather than being discarded as transport errors. An ExtremeXOS command can return status 250 with complete output; the caller must distinguish a command status, a device CLI error and the completeness of the returned answer. Neither a nonzero status nor a complete answer alone establishes semantic success.

Credentials and temporary workspaces keep the cleanup and interrupted-call boundaries documented above. [Generic platform boundaries](../../../docs/verified-support.md#operator-responsibility) and [compatibility evidence limits](../../../docs/compatibility-boundaries.md#catalogue-and-parser-coverage) describe the scope without deployment identities or execution logs.
