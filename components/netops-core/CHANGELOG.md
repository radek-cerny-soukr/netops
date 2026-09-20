# Changelog

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
