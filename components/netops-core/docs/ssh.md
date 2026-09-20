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
`NumberOfPasswordPrompts=1` and `PubkeyAuthentication=no`, which keeps a failed password a single
failure instead of a prompt loop or a silent fallback to a key.

`UserKnownHostsFile` points at a file inside the workspace of this one call, written from the host key
line the caller passes in. Trust comes from the pin in the inventory, never from a file on the host
that runs the command. The options of a legacy profile (`legacy_ssh.openssh_options`) are appended
**after** the base options, so an exception widens the algorithm list and cannot replace the hardening.

## Authentication

`run_command` takes a `vault.Credential` of kind `password` or `ssh-key`. Any other kind is refused
with `SshError` naming the credential kind and the two that can be used.

| Kind | What happens |
|---|---|
| `ssh-key` | the private key is written into the workspace with `O_EXCL` and mode 0600 and passed as `-i` |
| `password` | the password is written into `<workspace>/secret` with mode 0600, an askpass program reads that file, and the environment carries `SSH_ASKPASS`, `SSH_ASKPASS_REQUIRE=force`, `DISPLAY=none`, and `NETOPS_ASKPASS_FILE` with the path of the secret |

### Where the askpass program comes from

The client **executes** the askpass program, so it must live on a filesystem that allows execution.
By default the program is the small script `<workspace>/askpass`, written with mode 0700 next to the
secret. That is right on an ordinary host and wrong in a hardened container: the helper's Compose
file mounts `/tmp` and `/run` `noexec`, the workspace is created under `/tmp`, and a program written
there cannot be executed at all. Measured in the published 0.3.0 image on 19 September 2026: an
execute-permission check on the written script answers false and `execve` fails with `EACCES`, while
a program outside those mounts runs and reads a file inside them without trouble - `noexec` stops
execution, not reading.

A deployment that mounts its temporary directory `noexec` therefore ships the program elsewhere and
names it in `NETOPS_ASKPASS_PROGRAM`; the helper image installs `netops_core/askpass.py` as
`/usr/local/bin/netops-askpass` and sets that variable. The named program must be a regular file,
executable by this process, and not writable by group or other, because it is the program the
password is handed to. The secret itself stays in the workspace either way.

Both paths are checked before the client is started, so a deployment where the password could not be
handed over is refused with a message naming the reason and the variable, instead of failing later
as an authentication error that looks like a wrong password.

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
cannot grow memory either and cannot block by filling its pipe. The deadline covers the whole
receive: when `timeout_seconds` passes the client is killed and the call is refused.

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
budget is killed and the scan is refused with `SshError`, the same as an oversized command answer;
the `run=` argument stays the seam the tests use.

## The workspace

Every call creates its own directory with `tempfile.mkdtemp(prefix="netops-core-")` and mode 0700. It
holds the `known_hosts` file, and the identity or the secret and the askpass script. The directory is
removed in a `finally` block, so it is gone after the call whether the command succeeded, failed,
timed out, or raised.

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
not recognize. The raw text stays on the exception as `said`, for a caller that has a place for it
that is not a message: an audit record, an operator's log. A caller that passes an error text on to
an agent or a report passes the classified sentence.

This is why the legacy remedy works the way it does: it is a fixed sentence of this module, triggered
by a marker in `said`, not an echo of what the device wrote.

The exit status separates two different events. The OpenSSH client reports its own failure - it could
not connect, could not authenticate, could not negotiate - as 255 (`CLIENT_FAILURE_CODE`); every other
code is the status the remote command itself ended with. So 255 and a timeout are refusals, and any
other code is a `Result` carrying `rc` and everything the command wrote. The transport does not judge
a command's own status: whether a non-zero `rc` is an error is a decision of the caller, who knows
what it asked for. The auditor refuses a snapshot unless `rc` is 0; the helper returns the output and
reports `rc`.

| Situation | Refusal |
|---|---|
| credential of another kind | `SshError` naming the kind |
| the askpass program cannot be executed, or `NETOPS_ASKPASS_PROGRAM` names something that is not an executable regular file, or one that group or other may write | `SshError` naming the variable and the reason, before the client starts |
| the client does not finish in `timeout_seconds` | `SshError` naming the host and the timeout; the client is killed first |
| the client writes more than `capture_max_bytes` on standard output | `SshError` naming the budget; the client is killed and no partial answer is returned |
| `capture_max_bytes` is not a whole number of at least 1 | `SshError` naming the value |
| exit status 255, or a status that is not a whole number | `SshError` carrying `rc` and `said`, whose message names a reason from `REASONS` and not the client's words |
| exit status 255, no `legacy_ssh` profile, and `said` mentions a failed negotiation | `SshError` with the remedy: the exception is written per device as `legacy_ssh`, the profile list is closed, and there is no global switch |

The remedy appears only when no profile was named. A device that already carries an exception and
still fails to negotiate gets the plain failure, because the exception it has is not the answer.

## Testing it

`run_command` takes the runner as an argument (`run=`, by default the subprocess runner), so the tests pass a recorder
that returns a `subprocess.CompletedProcess` and assert on the exact argument vector and environment:
`-F /dev/null` first, the hardening options in order, `UserKnownHostsFile` inside the workspace, the
legacy options after the base ones, the password absent from both the argument vector and the
environment values, mode 0600 on the identity file, the workspace removed after success and after
failure, and the remedy text present only without a profile.

## Measured against

Recorded 16 September 2026 with this code, from a host with OpenSSH 9.2, one command per call, the
host key pinned from a prior `ssh-keyscan`. Each row is one real device.

| platform | authentication | `legacy_ssh` | result |
|---|---|---|---|
| FortiOS 8.0.0 (offers ed25519, ecdsa and rsa host keys) | `ssh-key` | `null` | `get system status`, rc 0, 1576 bytes |
| FortiOS 8.0.0 | `password` through askpass | `null` | `get system status`, rc 0, 1576 bytes |
| ExtremeXOS 33.7 (offers only `ssh-rsa`) | `ssh-key` | `null` | refused before the credential was used: `Unable to negotiate ... no matching host key type found. Their offer: ssh-rsa`, rc 255, with the remedy naming `legacy_ssh` |
| ExtremeXOS 33.7 | `ssh-key` | `rsa-sha1` | `show version`, rc 0, 443 bytes |
| ExtremeXOS 33.7 | `password` through askpass | `rsa-sha1` | `show version`, rc 0, 443 bytes, byte-identical to the key run |

After every call the workspace directory was gone and the password file handed to the run had been
removed by the caller. The Ruckus access point has no exec channel and is measured in
[`session.md`](session.md).

Recorded 17 September 2026 with this code against an ExtremeXOS 33.7.1 switch: four of the read
commands the helper catalogue holds for that platform end with exit status 250 and still write their
full answer to standard output - a port detail of 2344 bytes, an empty IPv6 route summary of 168
bytes, an IPv6 neighbour lookup of 613 bytes ending in `Error: IPv6 subnet not on an interface`, and a
link-aggregation summary of 941 bytes. That is why a status other than 255 is a `Result` and not a
refusal: treating every non-zero status as a failed call would have thrown four working answers away.
