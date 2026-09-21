# Changelog

## 0.2.3 - 2026-09-21

- Add `load(..., names=...)` selection so callers retain only the credential objects their operation needs. The default full-store API remains compatible; the complete JSON is still parsed transiently, so this is not an isolation boundary between stores.
- Refresh the hash-locked release tooling and document its generator environment; Core still has no runtime dependencies or container image.
- Verify the installed askpass command outside the checkout with valid and missing-file inputs. The Core suite passed 839 tests with installed askpass available; release export and executable-mode checks passed.

This entry describes the current source version. Earlier entries are historical source records; use the repository release index for current downloads and commit history for superseded source. Previous artifacts may remain visible during a release transition and are retired only after replacement verification and archival. See the [release procedure](docs/releasing.md).

## 0.2.2 - 2026-09-20

The distribution now carries the askpass program as a command, and the source export keeps the
executable bit of every program it ships.

- `netops-askpass` is installed as a console script. A deployment whose temporary directory is
  mounted `noexec` names an askpass program in `NETOPS_ASKPASS_PROGRAM`, and until now an installed
  distribution offered none: the module file inside `site-packages` is written without the execute
  bit, so the transport refused it and such a host could not hand a password to the client at all.
  The command is installed executable and `NETOPS_ASKPASS_PROGRAM="$(command -v netops-askpass)"`
  is now a complete answer on any host that installed the package.
- The source export marks `src/netops_core/askpass.py` executable, as the repository does. The
  archives of 0.2.0 and 0.2.1 shipped it with mode 0644, which failed the packaged-program test of
  the archive itself and left the program unusable where it was needed most.
- A test compares the executable bit of every exported file against its source, so an export can no
  longer quietly drop or add one.

## 0.2.1 - 2026-09-20

Correction to the bounded receive: the timeout now holds for the whole life
of the client process, not only while it is still talking, and a client is stopped together with
everything it started.

- One deadline, the whole life of the process: the capped runner watched the clock only while
  standard output or standard error was open. A client that closed both streams and kept running was
  then waited for without any bound, so it came back as a success long after `timeout_seconds` had
  passed - a device, or anything in front of it, could hold a caller for as long as it liked by
  closing two descriptors. The runner now takes one monotonic deadline before it hands the client
  anything, and the final wait gets what is left of it; when it runs out the call is refused with the
  timeout it always promised. A slow client that keeps its streams open is refused exactly as before.
- The whole owned process group is stopped, not only the client: the client is started in its own
  session (`start_new_session=True`) and is stopped by signalling the whole group it leads, so a
  process it started itself - `sftp` runs its own `ssh` - cannot outlive the refusal, keep the pipe
  open, or stay behind as an orphan. A signal goes to the group only when the process this library
  started really leads one, so an injected runner cannot be made to signal a group it does not own.
- A cleanup guard owns the process from the moment `Popen` returns: a failure to register the
  selector, an error inside the reading loop, an overrun of `capture_max_bytes`, a timeout, or any
  other exception all leave through the same exit, which terminates, waits a short grace, and then
  kills - the group first, the client itself second - and reaps what it killed. Whatever the reason,
  nothing is left running and nothing is left as a zombie. Before, only the budget and the timeout
  killed anything, and a registration error or a broken read left the client running.
- A call that ends by itself sweeps its group too: a client that exits with a status of its own
  while a process it started keeps running used to leave that process behind as an orphan, because
  only a refusal cleaned anything up. After the client is reaped, whatever is left of its group is
  asked to end, given the same short grace and then killed. The answer of the call does not change -
  the status, the output and the moments are the client's own - and when the group is already empty,
  which is the ordinary case, the sweep costs one system call.
- The interactive session follows the same contract when it is closed: after the hangup the terminal
  sends, the client is asked to end, then the whole terminal group is signalled, so a process the
  device's shell started does not survive the session that owned it. The pseudo-terminal already put
  that client in its own session, so the group is the session's own and nothing else is touched.
- `run_command`, `netops_core.sftp.stat` and `netops_core.hostkey.scan` share the one runner, so the
  time contract and the cleanup are the same in all three; only a caller's own `run=` runner is still
  the caller's business.
- `docs/ssh.md` writes the time contract down and states plainly what `said` is for: it is the
  other side's text, unanonymized, for an operator reading it by hand - never something a caller
  forwards into a report, a log line or a model prompt on its own.

## 0.2.0 - 2026-09-20

Hardening release: every transport bounds what it reads from a device, a failure names a reason
instead of repeating the device's own words, and password authentication survives a temporary
directory mounted noexec.

- Bounded receive: `ssh.run_command`, `netops_core.sftp.stat`, `session.Session` and now
  `netops_core.hostkey.scan` no longer hand the client an open bucket. The default runner reads
  standard output up to `capture_max_bytes` and kills a peer that keeps sending past it; standard
  error keeps only its first `STDERR_MAX_BYTES`. The host key scan carries its own, much smaller default,
  `KEYSCAN_CAPTURE_MAX_BYTES` (256 KiB), because a host key answer is a handful of lines, never a
  configuration; the auditor no longer forces its own uncapped runner onto that scan either. The
  `run=`/`spawn=` seam stays for tests, so only the default, production path is capped (`docs/ssh.md`).
- Audit record: an advisory `flock` on a stable lock file beside the log (`.<name>.lock`) now covers
  the size check, the rotation and the write across processes, not only across threads inside one.
  The retention wording is corrected: `retained_segments` files are kept in total - the active one
  and `retained_segments - 1` rotated ones - not that many rotated files on top of the active one
  (`docs/audit.md`).
- Askpass program: password authentication now goes through an executable program instead of a
  script written into the workspace. By default that is `<workspace>/askpass`, mode 0700; a
  deployment whose temporary directory is mounted noexec instead names a program on an executable
  path in `NETOPS_ASKPASS_PROGRAM` - the package ships one, `netops_core/askpass.py`, mode 0755.
  Both paths are checked before the client starts, so a workspace that cannot execute the program is
  refused with a message naming the reason and the variable, instead of failing later as what looks
  like a wrong password (`docs/ssh.md`).
- Classified failure reasons: the message of an `SshError` or an `SftpError` now names a reason from
  a closed list (`netops_core.ssh.reason`) instead of repeating the peer's own standard error text. The raw text
  stays on the exception as `said`, for a log that is allowed to hold it; a device controls its own
  standard error, so echoing it into a message an operator or a model reads put attacker-controlled
  text - potentially a secret - there.

## 0.1.0 - 2026-09-19

First version of `netops-core`, the shared access layer of the `netops` family. It releases from
source and ships no image; it is standard library only and declares no dependency.

- Platforms: `ruckus_unleashed` joins the closed list as the platform without an exec channel.
- Platforms and legacy SSH: a closed list of canonical platform names with aliases, and named
  exceptions for old SSH algorithms, so an inventory string never reaches a command line.
- Host key trust: pins in `SHA256:` form, fingerprints computed from the key blob, a `ssh-keyscan`
  invocation with a timeout, and a `known_hosts` file written once per run with mode 0600. A scan
  that offers no matching key names the pin and the number of keys offered, never the keys.
- Credential store (file version 2): four kinds, `login` required for the two login kinds and
  refused for the other two, a value that never reaches a representation, a mode check of 0600 or
  0400, and a refusal for a vault path that is a symbolic link.
- Inventory (file version 2): the device fields both consumers share, one section per consumer,
  canonical platform names, IPv4 or DNS addresses only, and a host key pin required before a legacy
  SSH exception may be named.
- SSH transport: the OpenSSH subprocess with the hardening options, key and password authentication,
  a private workspace removed after every call, and a remedy text when a negotiation fails without a
  named exception. Exit status 255 is the client's own failure and stays a refusal; any other status
  is the remote command's own and comes back as a `Result` with its output, because an ExtremeXOS
  switch answers some read commands with status 250 and a complete answer (`docs/ssh.md`).
- SFTP transport: the OpenSSH `sftp` client with the hardening, the workspace and the legacy
  profile of the SSH transport, asked for the metadata of one remote path. The batch is a single
  `ls -ln` written to standard input, never a `-b` file, because `-b` makes the client append
  `BatchMode=yes` to the `ssh` command line and that would disable the askpass program a password
  needs (measured 17 September 2026, OpenSSH 9.2p1). A directory answers with a count and never
  with the names of its entries, and the timestamp is returned as `modified_ls`, the precision of
  `ls`, not a unix modification time (`docs/sftp.md`).
- Prompt cleaning: the device prompt removed from a one-shot answer by one rule shared by the
  auditor and the helper. The marker is `#` or `$`, because a FortiOS read-only account answers
  with `$` (measured 17 September 2026, FortiOS 8.0.0); only the first line and trailing lines
  equal to that prompt are touched (`docs/prompt.md`).
- Interactive session: the same client on a pseudo-terminal with `expect` and `send`, for devices
  without an exec channel or with a login inside the shell; errors carry counts, never the transcript.
  Measured against a FortiOS, an ExtremeXOS and a Ruckus Unleashed device (`docs/ssh.md`,
  `docs/session.md`).
- Audit record: one JSON line per event, a closed field set including `transport` and `rc`, a
  component name in every record,
  rotation with a fixed number of retained segments, and mode 0600.
- Release gates: `scripts/check_gates.py` with `core_stdlib`, `version_metadata`, and
  `release_content`; the release selector `scripts/create_release_artifacts.py` exports an
  allowlisted tree with `release-manifest.json` and `SHA256SUMS`; `sbom.cdx.json` is generated by
  `scripts/generate_sbom.py` and `requirements-release.lock` pins the release toolbox with hashes.
