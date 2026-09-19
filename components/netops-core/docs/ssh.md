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
| `password` | the password is written into `<workspace>/secret` with mode 0600, an askpass script `<workspace>/askpass` with mode 0700 reads that file, and the environment carries `SSH_ASKPASS`, `SSH_ASKPASS_REQUIRE=force`, `DISPLAY=none`, and `NETOPS_ASKPASS_FILE` with the path of the secret |

The password is never an argument and never a value in the environment of the `ssh` process: only the
path of the file that holds it is. The environment is built from nothing and is exactly `PATH`,
`HOME` (the workspace), `LC_ALL=C`, plus the askpass variables for a password.

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
| the client does not finish in `timeout_seconds` | `SshError` naming the host and the timeout |
| exit status 255, or a status that is not a whole number | `SshError` carrying `rc` and `said` |
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
