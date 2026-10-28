# NetOps changelog

## 1.0.4 - 2026-10-27

### Added

- Helper: opted-in FortiOS `config_read` and `config_diff`, with live identity and single-root VDOM checks, conservative streamed redaction, bounded in-memory captures, paged results and opaque comparison of hidden values.
- Helper: bounded FortiOS ping, traceroute, sniffer, session and flow diagnostics without a schema registry. Exact identity, interface, inventory and cleanup checks remain required; FortiGate-VM64 on FortiOS 8.0.2 build 0251 is an explicit measured identity.
- Helper: a separate FortiADC platform with live product identification. The first qualified read is `system_status` on FortiADC-KVM 7.6.7 build 0676; Auditor collection and Admin writes are not qualified.

### Fixed

- Helper configuration streaming accepts the initial FortiOS exec prompt and matching final prompt while refusing unexpected framing. Configuration tools can complete within the proxy deadline.
- Configuration captures bound memory and redacted bytes, retain completed pages without device rereads and compare hidden records by private object identity.
- Admin: FortiOS 8.0.2 build 0251 is refused during profile validation before safeguard installation or a device change; rollback on that build is not qualified.

### Changed

- The first start of 1.0.4 upgrades state of 1.0.3 under the instance lock and changes only its recorded product version. Older state must follow the preceding release procedures. The syslog audit format stays unchanged.
- `read_query_catalog` supports platform/query-prefix filters and bounded pages with `next_offset` and `catalog_sha256`. A default call returns the first page, so clients must follow pagination.
- Helper has 15 MCP tools; the product has 28 with Admin enabled and 22 with Admin disabled.

### Documentation and release process

- Explain the separate device credentials for Helper, Auditor and Admin and limit the FortiOS automation finding to the measured 8.0.2 build 0251.
- Clarify the quickstart's Compose failure handling, private audit exports, five-record audit tail and separate backup/restore variable blocks. Describe the upgrade from 1.0.3 to 1.0.4.
- Bound signing-test subprocesses, validate the test worker mode and retain unittest outcomes.

## 1.0.3 - 2026-10-26

### Fixed

- Gateway: the ASGI delivery of a buffered, audited response has one absolute 60-second deadline. During body delivery a receive watcher also detects http.disconnect, which the shipped uvicorn h11 send can otherwise report silently. Body writes are bounded to 32 KiB and a final nonterminal send checks backpressure. An observed disconnect attempts the interrupted audit tail and returns without an application exception; timeout, cancellation and unexpected receive- or send-channel errors are audited when possible and still propagate. Buffered response sequences are validated before the response audit commit. See [Response delivery](release/notes-1.0.3.md#response-delivery).
- Helper: the SSH connection to a runner host keeps the OpenSSH client message about a failed algorithm negotiation (log level `INFO` instead of `ERROR`) and reports it as `ssh_negotiation`, without the host or the offered algorithms. An SSH category (`ssh_host_key`, `ssh_negotiation`, `ssh_authentication`, `ssh_connection`) is reported only when the SSH client itself fails with exit status 255; any other exit status comes from the remote command and is reported as `remote_exec` or `ssh_transport`, as in 1.0.2. The category is decided by the last line of the client standard error other than the closing `Disconnected from ...` line of OpenSSH, matched against the exact OpenSSH client messages, and the Helper keeps the last 64 KiB of that output instead of the first, so a login banner of the runner, which the `INFO` level prints, neither changes the category nor pushes the real error out unless its last line reproduces such an OpenSSH message.
- Gateway: the delivery deadline starts after the response and its audit commit are recorded; it does not cover admission waiting, operation execution, audit persistence, or direct gateway error and health responses. Small buffered sends and a close after the monitored phase may go unobserved; completion is not proof that the client received or read the response. Inspect audit pending, the recorded response and the device before repeating an operation; never retry writes automatically.
- Health: `netops health` queries the roles at the same time and waits up to 5 seconds instead of 2 in total for their status answers, so single runs of the container healthcheck no longer fail while the Helper redacts an SSH output of 2 MB to 16 MiB on a slow CPU; a role that does not answer within these 5 seconds still fails the check, within the 10-second timeout of the container healthcheck.

### Changed

- Upgrade the state of NetOps 1.0.2: the first start of 1.0.3 converts its state under the instance lock and changes only the recorded product version, as the upgrade from 1.0.1 to 1.0.2 did. State of NetOps 1.0.1 is refused; it is upgraded to 1.0.2 first. The syslog audit format stays that of 1.0.2.

### Release process

- Remove the unused portable Helper contract runner `components/netops-helper/tests/run_tests.py`; nothing ran it since 1.0.0, which removed tests it still called.
- The privacy gate of the release reports also decodes canonical standard and URL-safe base64 text, within shared layer and byte limits, for its private marker and private path checks; decoded content that is not UTF-8 text is checked without its NUL bytes (UTF-16) and by its printable runs of at least 8 characters; the public host-name checks do not decode it, which avoids false host findings in Docker metadata embedded in Grype reports.
- The platform smoke check installs `python3` on hosts with apt before its checks.
- Each architecture SBOM is validated offline against the complete, pinned CycloneDX 1.7 JSON schema before a release candidate is written; the SBOM must list components and its root container must match the exact image name and architecture digest.
- The source privacy gate (`release/check_source.py`) skips only its domain check for the five vendored CycloneDX 1.7 schema files in `release/schema/cyclonedx-1.7/`, including the SPDX license schema, and only while each file matches its pinned SHA-256; every other check still applies to them.
- Open placeholders in the public documentation (`release/placeholder_gate.py`): the candidate workflow refuses to build a release candidate while its release notes are missing, its changelog has no section of its version or its public documentation carries a placeholder other than the acceptance placeholder of that version (`acceptance-X.Y.Z`) and the release-date placeholder (`release-date`) in the heading of its changelog section; these two are filled after the acceptance of the candidate digests, and the signing tool refuses to sign while the Markdown of the source checkout given with `-SourceDir` still carries any placeholder, its release notes are missing or the changelog section of its version has no date.

### Documentation

- Quickstart: script forms of steps 7 and 8, the Compose `Container ... Creating`/`Created` lines named as Compose progress on standard error, and an authenticated `tools/list` over `curl` in step 9 with how to find the step 9 requests in the audit.
- Quickstart upgrade: a `jq` filter that lists the `instance_start` records, `umask 077` in the variable block, the `-p` hint of `connection` explained for the new instance directory, and the directory of the previous instance found from its Compose label.
- Document the upgrade from 1.0.2 to 1.0.3 in the quickstart, including a 1.0.2 instance that was upgraded from 1.0.1 (`~/netops-1.0.2`, project `netops-102`).
- Helper tools and README: `ftp_list` is refused in the shipped profile, and its engine path check over `sftp_roots` is lexical, unlike `sftp_stat`.
- Admin configuration: how NetOps reaches `unknown` with `safeguard_kept`, and how to prove a firing of the safeguard stitch on the FortiGate.
- README: the covered assets of the signed checksum list are named by kind.

## 1.0.2 - 2026-10-25

### Security

- Core SFTP: `sftp_stat` takes the last stderr line `Connected to <host>.` of the OpenSSH client as the end of the login banner. A banner line that began with `Connected to `, for example `Connected to the lab network`, made every call with roots fail and an empty directory unreadable, and together with a forged client line in the banner it let a directory reached through a symlink out of a root be listed. A device that controls its SSH banner could thus expose metadata outside an enrolled `sftp_roots` entry.

### Fixed

- The CA export hints that `init`, `connection` and `ca rotate` print now name the complete command `docker compose run --rm netops ca > netops-ca.pem`; they lacked the redirection to the file that the client configuration uses.

### Changed

- Upgrade the state of NetOps 1.0.1: the first start of 1.0.2 converts its state under the instance lock and changes only the recorded product version, as the upgrade from 1.0.0 to 1.0.1 did. State of NetOps 1.0.0 is refused; it is upgraded to 1.0.1 first. Apart from the SFTP banner fix and the CA export hints, the product code is unchanged, and the syslog audit format stays that of 1.0.1.

### Documentation

- Restructure the quickstart into numbered steps, each ending with a check, after blind installation tests of 1.0.1 on Fedora Server 44 and Ubuntu: Docker Engine from Docker's repository with the exact commands for Debian, Ubuntu, Raspberry Pi OS and Fedora, SELinux support in the Fedora Docker daemon before the download (checked with `docker info`), account access through the `docker` group or rootless Docker with its packages and the system daemon stopped, then `curl`, `jq` and cosign, and only then the download.
- Install cosign from the official Sigstore 3.x release (checked with v3.1.4) on every host family, check the package against the release checksums and link the Sigstore verification of cosign itself; README and quickstart now name the same requirement, cosign 2.5 or newer.
- Stop the download block at the first failed download, so cosign never runs on an incomplete set of files; the same for the upgrade download and the README.
- Add a separate step for an MCP client on the same host (`NETOPS_BIND_IP=127.0.0.1`, `NETOPS_SERVER_NAME=localhost`), also in the README, and describe the bind address, name resolution and host firewall for remote clients.
- Add a check of the running instance without an MCP client: `netops health`, `netops version`, an HTTPS request without the token refused with 401 and one with the token accepted with 200, and `audit stats`, including why `unauthenticated_rejections` is `null` before the first refused request.
- Document the order of the interactive `init` prompts, a uniform rule for `-T` and `< /dev/null`, the meaning of the manifest field `vulnerability_gate` (`needs-assessment`), a table of the tools that answer without an enrolled device with their arguments, and that exit status 0 of `claude -p` does not prove a tool call: the audit does.
- Add the download block to the README quick start and record Codex CLI 0.164.0 in the tested-clients table, tested against a NetOps 1.0.1 instance.
- Describe removing the NetOps image and the client configuration when an instance is removed.
- Document the upgrade from 1.0.1 to 1.0.2 in the quickstart in four steps: the syslog receiver of 1.0.1 stays unchanged, an instance of 1.0.0 is upgraded to 1.0.1 first, and a rollback starts the unchanged 1.0.1 instance without a receiver change.
- Make the upgrade runnable as written: concrete directories for the release files (`~/netops-1.0.2-release`), the new instance (`~/netops-1.0.2`) and the backup (`~/netops-backup`), no step that writes into the 1.0.1 instance directory, and `COMPOSE_PROJECT_NAME=netops-102` in the `.env` of the new instance, so that `docker compose` in its directory addresses 1.0.2 and not the stopped 1.0.1 state.
- Describe the acceptance of 1.0.2 in the README as it was run: CI in GitHub Actions on amd64 and arm64, a blind installation on Fedora Server 44 and Debian 13 on amd64, a blind upgrade from 1.0.1 on amd64 and a code review. Ubuntu, Raspberry Pi OS, arm64 hosts and rootless Docker, whose quickstart commands are new in 1.0.2, were not tested by a blind run for 1.0.2; their product code is unchanged since 1.0.1, whose acceptance covered them.
- Core SFTP: an embedded SFTP server that sends no permissions in its stat answer or returns `REALPATH` in another form (without the leading `/`, or with a volume prefix) makes `sftp_stat` refuse paths below a root (fail-closed); the path equal to a root works.

## 1.0.1 - 2026-10-25

- Support Docker Engine in rootless mode on all supported host families and architectures, including the SELinux label of the rootless Docker data on Fedora, applied before the first start of the rootless daemon. Rootless mode was not qualified in 1.0.0.
- Change the syslog audit format incompatibly: send every record, including a small one, as numbered `netops-syslog-part/1` part envelopes of consecutive 1024-byte chunks with the persistent record ID, the zero-based part number, the number of parts and the SHA-256 of the whole record. Each RFC 5424 message, header included, is at most 2048 bytes (the largest is 1618 bytes); the maximum record size stays at 8 MiB and the enlarged receiver limits of 1.0.0 are no longer required. Before the first start of 1.0.1, switch the receiver to a dedicated append-only archive of APP-NAME `netops` messages that stores each MSG followed by one LF, and keep the 1.0 archive separate; records still queued by 1.0.0 are sent in the new format. The data sent to the receiver grows about 1.6× for the measured 8277-byte record; overhead varies with record size.
- Retry a failed syslog delivery with the complete records under the same record ID, part mapping and SHA-256; only a successful TLS transport hand-over, not a storage acknowledgement, removes a batch from the queue.
- Add the offline command `netops audit reassemble --record-id <32-lowercase-hex>`. It reads the part archive from standard input in receiver line order and freezes the first complete, consistent set whose whole-record SHA-256 matches; exact retried duplicates are accepted and later conflicting parts, alternative sets or invalid rows cannot change it. Exit status 0 means a clean reconstruction; exit status 3 writes the same frozen record and reports `netops-syslog-reassembly-warning/1` warnings with the codes `late_conflict` or `late_invalid` and the original `line_number` on standard error; exit status 2 writes no record bytes on an argument, validation or input read error; a failed write to standard output also ends with exit status 2 and can leave partial output. `audit reassemble` reads each archive line up to a fixed limit, so a longer line is an invalid row: a validation error before the record is complete, a `late_invalid` warning after it. It needs no initialized instance, configuration, vault or running service and does not change the source archive.
- Limit password authentication in the shared Core SSH, terminal and SFTP transports to one password attempt per connection. A server that offers only keyboard-interactive authentication is refused before a password is sent.
- Refuse `init` while `NETOPS_SERVER_NAME` is still the `env.example` placeholder, before any state is written.
- Quote the complete Auditor refusal for a changed operator policy in the quickstart.
- Document the service identity of the TLS syslog receiver after its privilege drop and the owner, group and modes of the receiver certificates and of the new part archive.
- Cite the measured device refusals of the PoE and stacking controller queries and keep their causes apart: a hardware refusal for PoE and a firmware parse refusal for stacking on FortiOS 7.6.7; an SSH `rc` of 0 does not mean that the device query succeeded.
- Document the non-interactive first `helper_status` call for Claude Code and Codex, including the Codex `required`, `enabled_tools` and `approval_mode` settings, explicit tool permission and the model of each command.
- List the MCP clients and models tested for 1.0.1: Claude Code 2.1.310 on Linux, macOS and Windows and Open WebUI v0.12.3 with the local models Laguna XS 2.1 Q4 and gpt-oss-120b MXFP4 through llama.cpp `llama-server`, and add Open WebUI notes on CA trust, name resolution, a silently skipped server after an authentication failure and the size of `read_query_catalog` for small contexts.
- Name `cli_auth_credentials_store = "file"` in the Codex configuration example and explain that it stores the Codex provider sign-in in `auth.json`, separate from the NetOps token in `NETOPS_TOKEN`.
- Extend the quickstart after a blind installation test: link the official Docker Engine installation and require a new login after joining the `docker` group, install Claude Code on the host with `~/.local/bin` on `PATH` and sign in without a browser through `claude setup-token`, try each role without an enrolled device through `read_query_catalog`, `list_rules`, `audit_status` and `admin_status`, which returns `admin_not_configured`, and list the audited tool calls with their time in UTC and whether a response was recorded through a `jq` filter over `audit export`.
- Upgrade the state of NetOps 1.0.0: the first start of 1.0.1 converts its state under the instance lock and changes only the recorded product version; the `instance_start` audit record of that start, written once its roles are ready, names the previous and the new version. State of any other version is still refused and there is no downgrade.
- Refuse `init` and `token rotate` over state of another product version, including state not yet converted from 1.0.0, before any write. Repeating `init` no longer reports `Already initialized` for such state.
- Document the upgrade from the previous release in the quickstart: prerequisites, backup, verification of the new release files, restore of the backup into a new 1.0.1 instance with the same server name and port while the 1.0.0 instance stays unchanged, start and checks, explicit project names, several operators of one instance, an interrupted first start and rollback to the unchanged 1.0.0 instance with the receiver configuration of 1.0.0.
- Check the state before the first start of 1.0.1 converts it: the audit limits, the audit directory, the rejection summary, the local audit segments, the server name, the CA and server certificate files and their renewal, the Auditor configuration and, with Admin enabled, the Admin configuration. A refused first start does not convert the state: the gateway configuration still records `1.0.0`. The quickstart lists every check that the first start makes before the conversion, in its order and with the messages it reports, including the checks of the state directories and of the instance lock that every start makes. The Auditor and the Admin configuration are checked only as files and as JSON: a private file of the role user that holds a JSON object and, for the Auditor, text values for `tenant` and `catalog`. The roles of 1.0.0 refuse such a configuration when they start, except an Auditor configuration that 1.0.0 treated as absent, such as a dangling symbolic link; the first start of 1.0.1 now refuses it already before the conversion, and not only when the role starts after it. Everything else that the roles need, for example the values of `tenant` and `catalog` such as a value with a NUL character or an unknown catalog, the Auditor store and, when the Admin configuration lists devices, the complete Admin configuration, is still checked only by the roles after the conversion; when a role refuses it as the role starts, the state is already converted, the instance does not start and no audit record names the upgrade.
- Refuse a private state file without read permission for its owner also where NetOps reads it as root: the gateway configuration on every start and the files read by `ca`, `connection`, `token show`, `token rotate`, a repeated `init`, the `audit` reads and the operator commands. NetOps 1.0.0 read such files as root; its `token rotate` did not read the gateway configuration.
- Refuse to start when the audit directory `gateway/audit` exists but is not a directory owned by the gateway user with mode 0700, for example a directory with mode 0750 or a symbolic link, with local and with syslog audit. NetOps 1.0.0 started such an instance when the gateway user could write to the directory, for example a directory of the gateway user with mode 0750 or a symbolic link to such a directory.
- Treat only a missing rejection summary `gateway/audit/rejections.json` and a missing Auditor configuration `auditor/config.json` as absent, on every start and not only on the first start of 1.0.1. A dangling symbolic link, or a path whose existence cannot be checked, now stops the start; NetOps 1.0.0 treated it as absent, counted rejections from zero and started the Auditor with the default tenant and catalog. An existing file that its user cannot read stopped the start of 1.0.0 as well.
- Stop preparing the state directories on a repeated `init` of an initialized instance: it no longer resets the owner and mode of the state and runtime directories or reports unsafe role directories and data outside the 1.x layout. Every start still does.
- Report the running product version in the `version` field of `helper_status` instead of a fixed `1.0.0`.
- Keep the FortiOS rollback safeguard installed when the state after its fire time and grace differs from the state before the change and the stitch is still installed: FortiOS gives no device proof that the stitch ran, and NetOps 1.0.0 removed it before acting on the mismatch, so a stitch dispatched late was deleted, the change stayed and the operation ended as `revert-failed`. Such an operation now ends as `unknown` with the device blocked and the safeguard installed, so a late stitch can still return the previous state; this also applies when the stitch ran but a foreign value on the object differs, which 1.0.0 reported as `revert-failed`. Before unblocking, a person checks the object and removes the safeguard, because a new change is refused while it is installed.
- Update the Python dependencies for published security advisories: certifi 2026.7.22 to 2026.10.19 (GHSA-6q48-6c7w-9gw2, Critical: the bundle trusted a root whose intermediate CAs have compromised keys), FastMCP 4.0.5 to 4.1.2 (GHSA-7xgj-8392-5q4r, GHSA-vqqp-x5qm-5qp4), OpenTelemetry API 1.44.0 to 1.45.1 (GHSA-xcq7-p3pf-p88h) and openapi-pydantic 0.5.1 to 0.6.0, which FastMCP 4.1.2 requires.
- Update the container base image to Python 3.14.9 on Alpine 3.24. It fixes a race in the cleanup of `tempfile.TemporaryDirectory` (CVE-2026-12345).
- Check a `sftp_stat` path below an enrolled `sftp_roots` entry against the target that the SFTP server resolves in the same session: when a symbolic link in an ancestor or in the final component leads outside every resolved root, the call is refused and the metadata is not returned (reported in issue #6); a link replaced between that check and the listing remains a documented race. Lines that the SSH client prints before the SFTP session starts, such as a login banner or the OpenSSH warning about a key exchange without post-quantum protection, no longer make `sftp_stat` refuse the path.
- Limit the body receipt of an admitted authenticated request to 60 seconds, so that an incomplete body no longer holds an operation slot or the large-request lane without limit: when the deadline expires, the gateway records a `rejection` with reason `body_timeout`, `complete_body` false, the received byte count and `operation_executed` false, answers HTTP 408 `request_body_timeout`, closes the connection and dispatches nothing; a 4 MiB body needs at least about 70 KB/s.
- Known 1.0.1 limitation: the separate Helper SSH proxy to a runner host keeps both keyboard-interactive and password authentication. When a server offers both methods, one connection with an incorrect password can cause two failed authentication attempts, which may count under the runner account's lockout policy.
- Known 1.0.1 limitation: when the converting first start stops after the conversion, for example because a role refuses its configuration or the start is interrupted, no audit record names the upgrade; the only indirect evidence is the version in the last 1.0.0 records and the next 1.0.1 `instance_start`, which requires audit history kept from before the upgrade.
- Known 1.0.1 syslog limitation: the whole-record SHA-256 detects damaged or incomplete part archives but does not prove the authenticity of data controlled before the record was complete, and events suppressed before sending cannot be detected from the receiver archive.

## 1.0.0 - 2026-10-17

- Combine Core, Helper, Auditor and Admin in one Docker product with one dependency closure and product version.
- Provide one token-protected HTTPS Streamable HTTP MCP endpoint; no bundled AI clients.
- Isolate role processes and credentials using distinct UID, authenticated local IPC and an unprivileged steady-state runtime.
- Persist every supported request before dispatch and its response before delivery; refuse new operations when the audit cannot be committed.
- Support bounded TLS syslog forwarding or explicit local audit with rotation, retention and safe terminal output. Mark credential redaction visibly.
- Keep audit pending results independent of segment traversal order after backup and restore, including interrupted operations with a recorded response.
- Initialize an instance CA, automatically renewed server certificates, token and protected role data. Preserve identities on repeated init.
- Rotate the instance CA with `netops ca rotate` while the instance is stopped; warn from 30 days before expiry and report unhealthy from 14 days.
- Recover an interrupted local audit write with `netops audit recover`, which quarantines only the incomplete trailing bytes; audit reads, startup and the healthcheck name the condition.
- Refuse concurrent instances and operator configuration over live state; retain safeguards and explicit handling of unknown writes.
- Report refused, failed or uncertain operations as MCP errors (`isError`) and keep their full result content.
- Use English inventory roles `perimeter`, `internal` and `lab` (0.x used `perimetr` and `interni`).
- Name the Compose project `netops`; additional instances need an explicit `docker compose -p`.
- Report role configuration failures using fixed schema fields and reason codes without echoing input values; preserve useful reasons when input contains short words or schema names.
- Import Auditor snapshots and validated policies into private persistent state using create-only names; require a durable operator intent before reading import input.
- Write Auditor SARIF output privately (mode 0600) and refuse links or foreign files as the output path.
- Use digest-pinned Linux images for amd64 and arm64; qualify exact distribution bytes before the user's personal signature.
- Known 1.0 syslog limitation: audit records up to 8 MiB plus framing exceed the RFC 5425 minimum interoperability baseline. Receivers may truncate or discard oversized messages; default settings do not guarantee complete audit. Use explicitly configured rsyslog 8.2512 gtls with `maxMessageSize="9m"` and imtcp `MaxFrameSize="9437184"`; see [Syslog delivery](docs/architecture-1.0.md#syslog-delivery). General interoperability with default RFC-compliant receivers requires a later build.
- Known 1.0 limitation: there is no supported provisioning path for the schema registry/library files of Helper `schema_read` and `fortios_diagnostics`, the extra input files of advanced Auditor `--suppressions`, `merge-sarif` and `schema-check`, or file-based Admin offline/schema workflows. See [Helper configuration](docs/helper-configuration.md), [Auditor workflows](docs/quickstart-1.0.md#auditor-operator-workflows) and [Admin workflows](docs/admin-configuration.md).

Historical 0.x documentation and component changelogs are in [the byte-preserved archive](docs/archive/0.x/ARCHIVE.md). No 0.x data migration is provided and previously published releases remain unchanged.
