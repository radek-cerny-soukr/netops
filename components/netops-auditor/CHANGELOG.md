# Changelog

## 0.2.9 - 2026-10-06

- Update locked PyJWT to 2.15.0 to reject deeply nested JWT payloads with DecodeError.

- Report unmeasured source/target types, option choices and integer bounds as unknown upgrade checks. Map every schema finding family to its fixtures and distinguish those integrity checks from CIS and FortiOS 8.0.0 hardening rules.

- Check each configured integer list item against the target schema instead of parsing the complete list as one integer. Empty lists remain absent; malformed items report incomplete coverage.

- Add optional catalog checks on explicit global and VDOM snapshots, distinct finding identities per VDOM and a pinned MCP catalog coverage view. Unmeasured scopes and interface ownership remain unevaluated.

- Treat empty schema reference values as absent; real missing object names still produce findings.
- Add schema-check for all measured configured reference attributes, preserving VDOM and nested parent keys, and optional comparison against a target firmware schema. Missing metadata and partial snapshots report incomplete coverage. Firmware identity is operator-declared; schema comparison does not simulate migration or establish CIS compliance.
- Expose finished operator-pinned schema reports through the read-only MCP server, bound to its tenant and an enrolled device with explicit coverage and pagination.


- FortiOS: a configuration with VDOMs as FortiOS prints it, where each `config vdom` / `edit <vdom>` block is closed by `end` without `next`, ended in `cannot parse configuration: unterminated block` (exit code 2) instead of the `fortios.scope.vdom-unsupported` finding. Measured on FortiGate-VM 8.0.0 build0167 and 7.6.7 build3704 with multiple VDOMs. An `end` that meets an open VDOM entry directly under the top-level `config vdom` now closes the entry and the block; everywhere else `end` still closes one level, so a dump cut after an entry is still incomplete.
- `collect` no longer repeats the credential reference of a device, which may be a misplaced secret: a missing `--vault` and a credential of the wrong kind are `device <name> reads channel <channel> with a credential ...` instead of `... under credential <reference> ...`, and a reference the vault does not hold is `the credential of device <name> names no record of the credential store` instead of `the credential reference ...`. The auditor section of the inventory names the position of a refused value and its JSON type (a string with its length), no longer the value: `required_sections`, `source`, `channel` and `tls_fingerprint`, and `credential must be null for channel file` no longer repeats the reference. Covered by canary tests in `tests/test_cli.py` and `tests/test_inventory.py`, which failed on the unmodified source.
- Pin `netops-core==0.2.6`: the inventory and the vault are read without blocking, only as regular files and with a size limit, a key repeated within one JSON object of either is refused, the pinned host key is the only one OpenSSH trusts and the audit log is never opened through a symbolic link.
- Broken input is answered with one error line and a documented exit code, never a traceback or a hang; `tests/test_malformed_inputs.py` feeds every input of the CLI, the parsers and the MCP surface (FortiOS and EXOS dumps, policy, suppressions, SARIF, inventory, vault, store, every argument, the environment and every tool parameter of the MCP server) the same broken shapes: empty, binary, invalid UTF-8, BOM, CRLF, CR, U+2028 and NUL breaks, a 4 MiB line, deep nesting, duplicate keys, wrong types, Unicode digits, missing and extra fields, a truncated file, and a symbolic link, FIFO, directory or device in place of a file. It caught and this release fixes:
  - FortiOS: `config` and `edit` blocks nested deeper than 64 levels (`l1_fortios.MAX_DEPTH`) are refused as `cannot parse configuration ...: line N: blocks nest deeper than 64 levels` (exit code `2`). The parser's memory grew with the square of the depth: 100000 nested `config` lines (1.8 MB) ended in `MemoryError` under a 2 GiB limit and in the kernel's OOM killer without one.
  - FortiOS: an `admintimeout` or `admin-lockout-threshold` of more than 10 ASCII digits leaves its rule `not-evaluated` with `value-not-numeric` (exit code `3`) instead of a `ValueError` traceback from Python's limit on integer conversion (4300 digits).
  - `merge-sarif --output` is opened without blocking and must be a regular file or not exist yet: a FIFO nobody reads used to block the command for good, now it is `error: cannot write SARIF ...` (exit code `2`).
  - A `--store` or `migrate-suppressions --output` path the system refuses (a name longer than the file system allows) is an error line instead of an `OSError` traceback; the MCP server refuses such a `NETOPS_AUDITOR_STORE` as a configuration error.
  - The source of the `file` channel holding a NUL character is refused as `path holds a NUL character` instead of a `ValueError` traceback.
  - An argument that is not valid UTF-8 (`--tenant $'\xff'`) is refused with `error: argument tenant is not valid UTF-8` (exit code `2`); written into the report it ended in a `UnicodeEncodeError` traceback on a strict UTF-8 output.
  - A JSON string with an unpaired surrogate escape (`"\ud800"`) in a suppression file or a `merge-sarif` input is not valid JSON; before, it ended in a `UnicodeEncodeError` traceback. Such a text argument of an MCP tool is a tool error instead of an unhandled exception.
  - A tool error of the MCP server repeats at most 500 characters of the refused message; a 100 kB `rule_id`, `device` or `severity` was repeated whole.
- Malformed input no longer ends a run with a traceback: a FortiOS `admintimeout` or `admin-lockout-threshold`, an EXOS VLAN tag or a REST port written with non-ASCII digits such as `²` (the two FortiOS values are then not numeric, see the entry on `value-not-numeric` below, the tag is outside the `vlan_tags` policy, the port is refused before any connection), a `merge-sarif` input whose run, tool, driver, rules, results or devices are not of the expected JSON type (issue #1), a policy, suppression or SARIF file nested deeper than the JSON parser allows, and a `--store` file that is not a SQLite database (CLI and MCP surface). The last three are refused with exit code `2`.
- A key repeated within one JSON object of a suppression file or a `merge-sarif` input is refused; before, the last value won, so a second `expires` could silently extend a suppression. The operator policy already refused it.
- FortiOS: a quoted value that ends with an escaped backslash (`set comments "folder\\"`) no longer ends the run with `unterminated quoted value`; quote and escape handling is the same when the dump is split into statements and when a statement is split into words (issue #1).
- FortiOS and ExtremeXOS: a line ends only at `\n` (and `\r\n`). A U+2028, U+2029, U+0085, form feed or lone carriage return inside a value no longer shifts the line numbers of the findings (FortiOS) or refuses the snapshot (ExtremeXOS).
- `collect`: a FortiOS dump that stops inside a block or a quoted value is reported as `<platform>.snapshot.incomplete` with the evidence field `unterminated_line` and exit code `3`, instead of `error: policy cannot be evaluated (ParseError)`. `run` refuses such a file as before, now naming the file and the line.
- An error of the operator policy or of the configuration parser names the file and keeps the parser's message (line and column of a JSON error, line of a FortiOS statement) instead of the bare exception class.
- `--policy` must be a regular file of at most 256 KiB; it is opened without blocking and read no further than the limit plus one byte, so `/dev/zero` or a pipe is refused as `not a regular file` (also a pipe nobody writes to, which used to block the run in `open`) and a longer file as `larger than 262144 bytes`.
- Every other input file is read the same way, so `/dev/zero`, a pipe nobody writes to or a huge file no longer hangs a run or exhausts its memory: `--config` and the source of the `file` channel (64 MiB, `collect.MAX_SNAPSHOT_BYTES`), `--suppressions` and `NETOPS_AUDITOR_SUPPRESSIONS` (4 MiB, `suppressions.MAX_SUPPRESSIONS_BYTES`) and every `merge-sarif` input (64 MiB, `sarif.MAX_SARIF_BYTES`). Such a file ends the command with exit code `2` and one line; a suppression file that is not UTF-8 is a `SuppressionError` instead of a traceback. The inventory and the vault get the same limits from netops-core 0.2.6, which the auditor now pins. See `docs/configuration.md`, "Input files and their limits".
- Concurrent openers of one store, also of a file that does not exist yet, all succeed: the schema and its `PRAGMA user_version` are written in one `BEGIN IMMEDIATE` transaction, so a second process no longer sees the tables without the version and refuses the store as schema version 1. A store that already holds the whole schema is opened without a write.
- An SQLite error after the store was opened (`database is locked` after the five-second wait, `database disk image is malformed`) ends `run`, `collect` and `status` with `error: store <file>: <message>` and exit code `2` instead of a traceback. The MCP tools `audit_status`, `list_findings`, `finding_detail` and `compare` turn such an error, a store that cannot be opened and an unreadable suppression file into a tool error with that text instead of an unhandled exception.
- FortiOS: an `admintimeout` or `admin-lockout-threshold` that is not written in ASCII digits (`thirty`, `-1`, `1.5`, `²`) leaves `fortios.mgmt.idle-timeout` or `fortios.mgmt.lockout-threshold` `not-evaluated` with the reason `value-not-numeric` and the run exits with `3`; before, the rule was `evaluated` without a finding, which read as "nothing found".
- Documentation: a truncated ExtremeXOS dump is detected only as far as `required_sections` reaches, because `show configuration` ends with the last module and carries no closing marker (`docs/channels.md`).
- `run` and `collect` judge suppressions of the audited device only: an item for another device of the same tenant is no longer reported as orphaned or expired, the same as over MCP.
- `fortios.management.address-unused` is linear in the size of the dump (8000 addresses in 0.02 s, where 2000 took 2.4 s before on the same machine).
- The baseline and the previous evaluated run are read inside the write transaction that records the new run, so a concurrent run can no longer change them between the read and the write.
- MCP `list_findings` and `finding_detail` give every finding a `rule_status` (`status` and `reason` of its rule in the latest run), so a finding carried across an incomplete snapshot says why it is `not-evaluated`.
- Report a machine-readable state for every rule of the catalogue. The JSON report of `run` and `collect` gains `rule_status` (rule id to `status`, `reason` and `required`) and `evaluation_complete`; `status` is `evaluated`, `not-evaluated` or `unsupported`, so a rule that found nothing is no longer indistinguishable from a rule that could not read its input. A rule that is not evaluated reports no findings, and its earlier findings are listed in `not_evaluated` instead of `gone`. The existing `evaluation`, `not_evaluated` and `rule_coverage` fields keep their meaning. The SARIF device properties carry `rule_status` and `evaluation_complete`; the store records the states of every run in a new `rule_status` table (created on the next write, no migration), and the MCP `audit_status` and `compare` answers carry them (`rule_status`, `not_evaluated_rules`).
- `run` and `collect` exit with the new code `3` when a mandatory rule was not evaluated (an incomplete snapshot, an unsupported FortiOS scope, an unterminated EXOS UPM profile). The report is still printed and recorded. The GitHub Action finishes the SARIF file and then fails. See `docs/configuration.md`.
- ExtremeXOS: a `configure vlan ... add ports all` or a port range across slots (`1:1-2:4`) no longer ends the run with a traceback. Both are expanded from the port list the snapshot carries in `configure vr <name> add|delete ports`; where that list is absent the affected management rules are `not-evaluated` with the reason `unresolved-port-list`, and a rule named in `required_rules` refuses the run as before.
- ExtremeXOS: the script body of a UPM profile (`create upm profile` up to the closing `.`) is no longer read as active configuration by any rule; before, commands inside an unused profile hid the SNTP, syslog and Telnet findings. An unterminated profile leaves the whole catalogue `not-evaluated`.
- ExtremeXOS management rules are evaluated over the VLAN and port commands the snapshot carries, not over the `# Module vlan configuration.` header: the same content without the header is now evaluated, and the header without content is `not-evaluated` (`no-vlan-content`).
- FortiOS: a dump wrapped in a top-level `config global` block without a `config vdom` block fires `fortios.scope.vdom-unsupported` (object `global`, count 0) instead of returning a clean result with the hardening rules silently skipped.
- `collect`: a required section header inside a multi-line quoted FortiOS value, or inside an EXOS UPM profile body, no longer counts as a present section.
- The operator-policy history of a device is checked inside the same write transaction as the new run, so two concurrent runs with different policies can no longer both be recorded into one store.
- `fortios.management.address-unused` counts an address as used only when its name appears in an attribute that can reference an object. Attributes whose name contains `password`, `passwd`, `passphrase`, `pwd`, `secret`, `psk`, `key`, `community`, `token`, `comment` or `description`, and `name` in `system snmp community`, are no longer compared, the same list the planner of netops-admin leaves out. Before, a secret or a comment equal to the name of an otherwise unreferenced address hid the finding, and the `audit_findings_before` of an Admin `preview delete` could confirm a guess of a secret that way. A real reference (`srcaddr`, `dstaddr`, `member` and any other attribute) still marks the address as used.
- MCP: a `QueryError` (an invalid `severity`, `state`, `since` or `stale_after_hours`, an unknown rule in `rule_detail`, a run of another device in `compare`) is a tool error with the query message, the same as a store error; before, it surfaced as `Error calling tool '<name>': ...` and the server logged a traceback. `list_rules` and `rule_detail` are guarded the same way.
- Candidate schema reads and scoped catalogue/reference/upgrade reports were checked with FortiGate-VM64-KVM 7.6.7 build3704 and 8.0.0 build0167 in early October 2026, preserving configuration exactly. Offline security, concurrency and malformed-input cases have their own regressions. These runs do not establish physical-model or complete CIS coverage; see [current candidate validation](../../docs/verified-support.md#candidate-validation-3-4-october-2026).
- Documentation: the README and the release guide install from the verified release archives (`SHA256SUMS` and the Sigstore bundle) and no longer name `pip install netops-auditor` as the way to install this version.

## 0.2.8 - 2026-09-26

- Pin `netops-core==0.2.5`. The host key scan now asks for one key type at a time, so a collection no longer uses up the VTY lines of a small device before its own connection, and it works with the OpenSSH 10.0p2 `ssh-keyscan`.
- Pass the device's `legacy_ssh` profile to the host key scan as well as to `ssh`, so a device with `legacy_ssh: "rsa-sha1-dh14"` (classic Cisco IOS, SHA-1 key exchange only) can be pinned and collected. The auditor has no Cisco rule catalogue; the change keeps the channel consistent with the core.
- Documentation: the collection channels describe the scan and the profile, and the `ssh` channel records the collection from the EXOS-VM 33.6.1.14 virtual switch on 25 September 2026 (9 EXOS rules, one correct finding, a byte-identical snapshot with the new scan) and from an X440-G2 with ExtremeXOS 33.7.1.6 before the release (the same snapshot and findings as 0.2.7).

## 0.2.7 - 2026-09-24

- Publish the package on PyPI as `netops-auditor`; `pip install netops-auditor` installs the pinned core with it. `pyproject.toml` gains the README as the package description, project URLs and classifiers, and declares the licence as the SPDX expression `MIT` with `license-files`; the build requirement rises to `setuptools>=77`.
- Pin `netops-core==0.2.4`, which differs from 0.2.3 only in its package metadata. Link the README to its documents by absolute URLs, so that they also resolve on the PyPI project page, and describe installing from PyPI. No change to the code or the rule catalogues.

## 0.2.6 - 2026-09-24

- Add `run --sarif`, a SARIF 2.1.0 report with rule metadata, file and line locations, the finding fingerprint as a partial fingerprint and suppressions, and `merge-sarif`, which combines the reports of several configurations into one run.
- Ship a composite GitHub Action (`action.yml`) that audits committed configuration files offline and writes one SARIF file for code scanning. Every action it uses is pinned to a commit.
- Add twelve FortiOS hardening rules from the CIS FortiGate 7.4.x Benchmark v1.0.1 and the FortiOS 8.0.0 Best Practices: USB auto-install, static key ciphers, strong crypto, legacy TLS on the web GUI, idle timeout, lockout threshold, the default admin account, HTTP or Telnet administration, SNMP v1/v2c communities, accepting policies with service ALL, policies with logging disabled and LDAP without TLS. Defaults were checked in the CLI Reference of 7.4.12, 7.6.7 and 8.0.1; a rule reports a missing setting only where the default is the weak value in all three. The three existing rules that match a CIS recommendation carry its reference. See [`docs/cis-mapping.md`](docs/cis-mapping.md).

## 0.2.5 - 2026-09-24

- Add twelve management rules: unused addresses and VLANs, address and VLAN policy, empty/dangling/cyclic groups, DHCP conflicts and subnet constraints, port VLAN allowlists, native VLAN consistency and description convention.
- Add validated operator policy files to run/collect, explicit management-rule coverage and mandatory-rule refusal. Bind stored runs to the policy digest.
- Include positive and negative fixtures for every added rule, plus malformed-policy, large-graph, DHCP-type and UPM-body regressions.

## 0.2.4 - 2026-09-21

- Keep HTTP sockets alive through complete response consumption, including Connection: close, HTTP/1.0 and EOF-delimited bodies. Reject truncated Content-Length/chunked responses and preserve the absolute deadline for slow peers.
- Preserve mode 0600 when migrating suppressions, independently of umask, with atomic no-overwrite output.
- Use stable EXOS SNMP object identities rather than positional keys. `exos.snmp.default-community` advances to rule version 2: review and recreate affected baselines and suppressions from a fresh report; ordinal identities cannot be mapped safely without the original configuration. Digests are identifiers, not encryption.
- Prevent incomplete collection and scope-limited evaluation from declaring unobserved findings gone. See [configuration and upgrade guidance](docs/configuration.md).
- Pin Core 0.2.3 and refresh hash-locked tooling and optional MCP dependencies. All 1,097 tests passed; clean source-export installation verified both valid and invalid CLI input. This component remains a source-only release.

This entry describes the current source version. Earlier entries are historical source records; use the repository release index for current downloads and commit history for superseded source. Previous artifacts may remain visible during a release transition and are retired only after replacement verification and archival. See the [release procedure](docs/releasing.md).

## 0.2.3 - 2026-09-20

Follows `netops-core` 0.2.2, pinned as `netops-core==0.2.2`.

- The installed distribution carries the rule catalogues. `catalog/fortios.json` and
  `catalog/exos.json` were not package data, so a `pip install` produced a package whose `run`
  ended with exit code 2 on a missing catalogue; tests running from `src` never touched that path.
- The command line is installed as `netops-auditor`, the name every message and every example in
  the documents already used.
- The REST collector holds one deadline over the whole answer. The clock was checked between reads,
  but a read blocks on the socket's idle timeout rather than on the remaining budget, and the
  response headers were parsed before any check at all: a peer answering one byte at a time held a
  collection roughly five times past its timeout, measured. The deadline now reaches every receive.
- `migrate-suppressions` publishes its output atomically under a name that must not exist yet: a
  destination created between the check and the write was silently truncated, and a dangling
  symbolic link was followed to wherever it pointed. Both are refused now.
- The MCP surface started without `fastmcp` says so in one line and exits with status 2, instead of
  raising an import error, and `docs/configuration.md` documents how it is started.
- Six FortiOS rules carry the `refs` of the running release, mirroring the EXOS rules.

## 0.2.2 - 2026-09-20

Follows `netops-core` 0.2.1, pinned as `netops-core==0.2.1`. Two breaking changes to files the
auditor reads: the suppression file goes to version 2 and the store carries a schema version. Both
are refused fail-closed with the migration command in the message, and both migrations are explicit
CLI steps that never run on the side.

- **Bounded REST body.** The `fortios-rest` collector assembled the answer block by block with a
  time limit and no byte limit; a synthetic answer of 300 blocks of 65,536 bytes was accepted whole,
  19,660,800 bytes of it. A budget is now measured **before** each block is kept, so an oversized
  answer is dropped while it is still arriving: `--max-response-bytes` of `collect`, default
  `8388608` (8 MiB), a number sized for a configuration export rather than copied from the 2 MB cap
  `netops-helper` puts on the output of a command. The request, the response headers and every block
  of the body now share one deadline instead of the body alone carrying it, an HTTP status other
  than `200` ends the call after a small head of the answer that is thrown away rather than after
  the whole body, and both refusals name a reason from a closed list and the limit - never a word
  the peer wrote. The `ssh` channel keeps its own cap, the bounded receive of `netops_core.ssh`.
- **The tenant is part of a finding's identity.** The fingerprint is the sha256 over `rule_id`,
  `rule_version`, `tenant`, `device` and `object_key`, joined by `\x1f` in that order, and it is
  computed by one function that the report, the store and the suppression reader all call - the
  second copy that lived in `suppressions.py` is gone. The same device audited for two tenants now
  produces two different fingerprints, so one tenant's waiver can no longer reach the other's
  finding. The version of the rule catalogue stays out of the fingerprint on purpose.
- **Suppression file version 2 (breaking).** `tenant` is a required document field; a version 1 file
  and a file without a tenant are both refused, naming
  `netops-auditor migrate-suppressions --input <old file> --output <new file> --tenant <tenant>`.
  That command rewrites every fingerprint for one tenant, checks each item against its old
  fingerprint first, never writes over its input or over an existing output, and prints a count and
  a path - nothing out of the document it read. A file written for two tenants was never one file;
  migrate it once per tenant.
- **The CLI and the MCP surface refuse alike.** Both load a suppression file through one function,
  `suppressions.load_for_tenant`, so the read-only server can no longer stay silent where the CLI
  refuses. The MCP surface stays read-only: it holds no migration and writes nothing.
- **Store schema version 2 (breaking).** The database carries `PRAGMA user_version`. Opening an
  older store is a readable error instead of a silent run - on the CLI and on the read-only server
  alike - and `netops-auditor migrate-store --store <file>` recomputes the fingerprint of every
  stored finding from the tenant of its own run and rewrites the baseline with the same mapping in
  one transaction, so the count of findings, the baseline and the four states survive it and nothing
  appears twice. A finding whose run names no tenant stops the migration and changes nothing.
  Recording a finding whose tenant is not the run's tenant is now a store error, as it already was
  for the device.
- The six FortiOS rules carry `refs` into the *FortiOS 8.0.0 CLI Reference*, the release running on
  the devices this catalogue was written for.

## 0.2.1 - 2026-09-20

Follows `netops-core` 0.2.0, pinned as `netops-core==0.2.0`.

- Bounded receive: the `ssh` channel inherits `netops-core`'s bounded receive on every transport it
  uses - `run_command`, and now the `ssh-keyscan` host key scan as well. `collect_ssh` no longer
  forces its own uncapped runner onto that scan, so the shared, capped default applies there too.
- Classified failure reasons: a `CollectError` raised from a failed `ssh` call now carries the
  reason the shared `ssh` transport of `netops_core` names from a closed list, not the device's own
  standard error text - that text is the device's to write and can carry attacker-controlled content.
- `exos.time.no-sntp-client` goes to rule version 2: `enable ntp` or a `configure ntp server add`
  entry carrying a host now silences it too, closing its one documented false positive - a switch
  synchronizing its clock over the NTP client instead of SNTP.

## 0.2.0 - 2026-09-19

The auditor stops carrying its own access layer and takes it from `netops-core`: the inventory, the credential store, the host key trust and the SSH transport are now the shared ones of the family, pinned as `netops-core==0.1.0`. What stays here is the policy - the `auditor` section of an inventory entry, which kind of credential a channel takes, the step table of a platform, and the audit itself. The component is no longer standard library alone; there is no index behind the pin, so that release required the matching `netops-core` source archive beside it (historical requirement; those archives are no longer published), and in this repository the tests and CI take it from `../netops-core/src`.

- **ExtremeXOS and Switch Engine are an audited platform, not only a snapshot.** `collect` no longer refuses a device whose platform is `exos` - the message `the auditor holds no rule catalog for it` is gone - and `run --platform exos` reads a `show configuration` dump. The platform now picks both the parser and the catalogue; `l1_exos.py` is the second L1 parser and there is no shared model behind them, because none of the ten rules needs one yet.
- **L1 EXOS parser.** `show configuration` is a flat list of imperative commands, not a tree: the parser keeps every line as it was and builds one record per command carrying its 1-based line, the module declared by the `# Module <name> configuration.` header above it, its tokens split on whitespace with double quotes respected, and the command text. It is lossless - the original bytes come back from `serialize()`, comments, blank lines and line endings included - and an unterminated quote is a parse error naming the line.
- **Four EXOS rules, all class `fakt`.** `exos.snmp.default-community` (high) reports a community entry whose plainly written index, name or string is `public` or `private`; `exos.mgmt.telnet-enabled` (medium) reports Telnet, which 33.7.1 leaves enabled by default, unless `disable telnet` is the last Telnet command of the dump; `exos.logging.no-syslog-target` (medium) reports a switch with no `configure syslog add` target; `exos.time.no-sntp-client` (medium) reports a switch with neither `enable sntp-client` nor a `configure sntp-client primary` entry. Every rule names the command entry of the *ExtremeXOS v33.7.1 Command References* it rests on in `refs`, and carries in `known_false_positives` what it cannot see - that `enable syslog` never appears in `show configuration`, that the NTP client is a feature the time rule does not read, and that a community written with `hex` or `encrypted` is not compared at all.
- **A community string never reaches a finding.** The evidence of `exos.snmp.default-community` names the field that matched, the fixed first four words of the command and the dictionary, and nothing else; the value is absent from the evidence, from the object key and from the report. A second canary fixture, eleven marked secrets of an EXOS dump - account passwords, RADIUS and TACACS+ shared secrets, an SSH user key, community strings and SNMPv3 passwords - holds that boundary in the same gate as the FortiOS one, over findings, CLI reports, the store and every query.
- **The gates run per platform.** Positive and negative fixtures for each of the four rules, a clean fixture that yields nothing, one inserted defect yielding exactly one new finding, a byte identical report and store listing for the same input, and stability over a volatile field. `scripts/check_gates.py` needed no change: it already walked every catalogue in `src/netops_auditor/catalog`.
- **Verified over a real dump, not over a device.** Two `show configuration` backups of switches running ExtremeXOS 33.7.1.6: one produced no finding, the second produced one, `exos.time.no-sntp-client`, which is the documented false positive of a switch synchronizing over the NTP client. Four defects inserted into a copy of the first dump each produced exactly one new finding. The `ssh` channel has not pulled an EXOS configuration and handed it to this catalogue in one run.
- **Inventory is file version 2 (breaking).** A version 1 document is refused, naming the version found and the one expected. The common device - `name`, `platform`, `address`, `port`, `role`, `credential`, `host_key_fingerprint`, `legacy_ssh` - is read by `netops_core.inventory`; the auditor validates its own `auditor` section: `channel`, `source` (a path for `file`, `https://host[:port]` for `fortios-rest`, `null` for `ssh`), `required_sections`, `tls_fingerprint`. A device is the auditor's when that section is an object, so the field `consumer` is gone. The `ssh` channel is reached by the common `address` and `port`, and every cross-check a channel makes on the common part - a credential refused for `file`, required for the two remote channels, a certificate pin required for `fortios-rest` and a host key pin for `ssh` - names the device and the field.
- **Credential store is file version 2 (breaking).** A version 1 store is refused. The kinds are the family's four, `login` belongs to the record, and the auditor holds the rule per channel: `fortios-rest` takes `api-token`, `ssh` takes `password` or `ssh-key`, and a record of another kind ends the run with a message naming the kind before anything is sent.
- **`--profile` is removed (breaking).** The login of an `ssh` session is the `login` of the credential, so the option that carried it is gone. The report field `collection-profile` now carries that login, `collection-credential-kind` names the kind of the record, and on `file` and `fortios-rest` the profile stays `unknown`.
- **Password authentication works on the `ssh` channel for the first time.** The transport is `netops_core.ssh`: a key goes to the client as a file of mode 0600, a password through an askpass script reading a file of the same mode, and neither reaches `argv` or a value in the environment. The auditor adds nothing to the options of the client, and a refused negotiation carries the remedy that names `legacy_ssh` from the shared transport.
- **SSH transport shared with the family.** `collect.py` lost its copy of the host key scan, the `known_hosts` file, the identity file, the argument vector, the environment and the subprocess call; it keeps the step table per platform, the preflight that refuses to change a device, the prompt cleaning and the `ChannelEvent` of every command. `collect_ssh` takes the device address and port, the credential and the host key pin, and both runners are injectable, so the test suite still never touches the network.
- **The prompt cleaning moved into `netops_core.prompt` and learned the read-only marker.** `collect.py` holds neither `PROMPT_PREFIX` nor a `_cleaned` of its own any more; a step marked `prompt=True` calls `prompt.cleaned(text, platform)`. The rule is unchanged - only the first line and trailing lines equal to that prompt, never the middle - except that the marker is now `#` or `$`. Measured on 17 September 2026 against FortiOS 8.0.0 on the exec channel: a `super_admin` account answers with `<hostname> # `, an account with a read-only profile with `<hostname> $ `, so under a read-only account the prompt used to stay in the snapshot and in its hash. The two hashes of a `ChannelEvent` and a `Snapshot` mean exactly what they meant before.
- **Supply chain:** `sbom.cdx.json` carries `netops-core` as the required dependency of the root component, `fastmcp` stays optional, and `scripts/generate_sbom.py` builds that graph from the pin in `pyproject.toml`. The gate `core_stdlib` accepts `netops_core` beside the standard library and refuses everything else as before.
- **Documentation:** `docs/inventory.md` is the `auditor` section and the cross-checks, linking the shared schema in `../netops-core/docs/inventory.md`; `docs/configuration.md` is the credential store of version 2 and the kind rules per channel; `docs/channels.md` loses the `--profile` row and points at the shared transport; `docs/releasing.md` says how `netops-core` gets beside the auditor.

## 0.1.0 - 2026-09-13

First release of `netops-auditor`: a configuration audit that collects a snapshot from a device, evaluates it against a catalogue of rules, and reports findings without ever changing the device. It releases from source and ships no container image; the component is standard library only, and `fastmcp` is needed for the MCP surface alone.

- Rule engine: L1 FortiOS parser with line numbers, the rule catalogue as data, an engine with a check registry, six rules, a SQLite store that never keeps the configuration, and a CLI with a text and a JSON report.
- Baseline and suppressions: baseline in the database, suppressions in a JSON file in the repository with a mandatory expiry and a fingerprint verified by recomputation, the four finding states `new`, `open-known`, `suppressed`, and `gone`, and a `status` subcommand for freshness.
- Collection path: inventory, vault, and the `file`, `fortios-rest`, and `ssh` channels, each documented with what it cannot do. The auditor never changes a device: with an active FortiOS pager the collection refuses instead of turning it off.
- MCP surface: six read-only tools over a store opened read-only; the server imports neither `collect`, nor `vault`, nor `inventory`, and two independent tests hold that boundary.
- Release gates: a positive and a negative fixture per rule enforced by data, a canary of twenty secrets, determinism, stability over a volatile field, a mutation test, and `scripts/check_gates.py` as the gate of a release.
- Gate over the released set: the gate `release_content` reads the file set from the release selector `scripts/create_release_artifacts.py` and scans every released text file against an allowlist of addresses, names, and markers, so the exported archive verifies itself without a repository next to it. The selector runs in a subprocess, so a rewritten selector cannot disarm the gate, and a missing one fails the gate closed. In a tree with no repository above it - which is what an exported archive is - the gate also holds the file set itself: every file must be in the release selection and in `release-manifest.json`, and every file those name must be present, so neither an added nor a removed file survives the gate.
- Legacy SSH per device: the inventory field `legacy_ssh` names a profile (today only `rsa-sha1`) that the `ssh` channel expands into `HostKeyAlgorithms=+ssh-rsa` and `PubkeyAcceptedAlgorithms=+ssh-rsa` for that one device. The profile is a name, never an algorithm list, so no inventory string reaches the command line; the field must be `null` for the other channels and the default stays on current algorithms. The collection report carries `collection-legacy_ssh`, so a run that used the exception says so. A failed `ssh` call now reports what the client wrote on stderr, trimmed and stripped of control characters, and a refused negotiation also says how the exception is written down.
- Documentation: `docs/inventory.md` describes the fail-closed inventory schema field by field, with the `legacy_ssh` exception, the error texts and a per-channel table; `docs/configuration.md` the vault and suppression schemas, the return codes, and the two fail-closed behaviours that end a whole audit; `docs/releasing.md` the source-only release and its four assets.
- Completeness per platform: a required section is named without the header its platform writes around it, and a section written as that header is refused instead of coming back as a gap that is not there. FortiOS opens a section with `config <section>`, ExtremeXOS with `# Module <section> configuration.`, so an EXOS snapshot is measured at all.
- Supply chain: `sbom.cdx.json` is generated by `scripts/generate_sbom.py`, committed, and regenerated and compared byte for byte during a release; it carries the empty dependency graph of a standard library component and `fastmcp` as an optional one. `requirements-release.lock` pins with hashes what the release toolbox installs to verify it.
- Repository: the component moved into the `netops` monorepo layout under `components/netops-auditor/`, carries its own `pyproject.toml`, `LICENSE` copy, and release selector, and is covered by the repository gate `scripts/check_release.py`.
