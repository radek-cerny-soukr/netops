# Execution: safeguard, journal, audit and what is measured

`netops-admin apply` executes one planned change on one configured device, FortiOS or ExtremeXOS. This page describes the sequence, the safeguard of each platform, where it was measured and what it does not guarantee.

## Sequence

1. Refuse a request whose `device` names another device than the one it is sent to. Take the device lock; refuse a `request_id` already used for different content, a blocked device, and a device with an unfinished operation.
2. Check that the journal and the local audit log can be written durably and that the audit export is not blocked.
3. Read, with the write account, a full configuration snapshot (collected by the netops-auditor collector, host key pinned) and check the accounts (see the platform sections).
4. Refuse when the account check fails (the device is also blocked, see below), when a safeguard of an earlier operation is still installed, or when a platform precheck fails.
5. Plan the change (see [planning.md](planning.md)) and require a valid device enrollment. Audit the before and predicted snapshots against the operator policy and require the selected operation's mandatory rule coverage and let the check account read the object; refuse when the auditor cannot evaluate or when the check account cannot read the object or sees it in another state than the snapshot. Write the journal record and the start event of the audit log, both synced to disk, before the first mutation.
6. Install the safeguard: a one-shot object on the device that runs the planned inverse a configured number of seconds after the device clock. Read it back and compare it with the plan; a safeguard that does not read back is removed and nothing else is done.
7. Apply the planned commands line by line over an interactive session and stop at the first line the device refuses.
8. Take a new snapshot, check the accounts again and compare the snapshot with the prediction: the object and the rest of the evaluated scope. Let the auditor evaluate the new snapshot: a new or changed finding of severity high or medium, or an evaluation that does not complete, stops the confirmation. Let the check account read the object: it has to see exactly the predicted state.
9. Confirm only when everything matches and enough time is left before the safeguard fires: take one more snapshot and verify the object and the rest of the evaluated scope while the safeguard is still installed, remove the safeguard, read back that it is gone, take a snapshot and verify them once more and, where the platform needs it, save the configuration and verify them again after the save. The time left is read before the last snapshot with the safeguard installed, so `confirm_margin_seconds` has to cover that snapshot and the removal; the snapshots after the removal no longer race the safeguard.
10. Otherwise do not confirm: wait until the safeguard has fired, take a snapshot, verify that the object is back to its previous state, remove the safeguard and, where the platform needs it, save the configuration. The wait follows the device clock until 20 s after the planned second and gives up after 980 s, the longest allowed `safeguard_seconds` (900) plus those 20 s and 60 s of slack; a wait that gives up ends `unknown` and blocks the device.

## FortiOS

The safeguard is a one-shot automation stitch whose `cli-script` action is the planned inverse. The inverse script is written with real newlines inside the quoted `set script` value; quotes and backslashes inside it are escaped. `set trigger-datetime` takes the date and time as two unquoted tokens. The account check requires that the write account sees in the administrator table exactly the configured accounts (by default only itself). FortiOS applies configuration immediately and keeps it; nothing is saved separately.

## Accounts and the check account

Every device has two accounts of the tool: the write account and a read-only check account. The check account reads the object before the change and after it (`show firewall address "<key>"` on FortiOS, `show vlan <key>` on ExtremeXOS); it cannot write, and its key is a separate credential. With `check_address` it connects to another management address of the device than the write account, so the check also takes another path; the host key is checked against the same pin. On ExtremeXOS the answer of the switch carries a non-zero exit status also when the query succeeds, so only a recognised answer counts: the object shown, or the message that no VLAN of that name exists. A VLAN without a description shows `None`; the profile refuses that word as a description.

The account check computes a fingerprint of the account entries (on FortiOS the entries the write account sees in `show system admin` together with their referenced access-profile permissions, on ExtremeXOS the `account` and `sshd2 user-key` lines of the snapshot) and keeps it after each operation that starts. A later operation refuses and blocks the device when the fingerprint differs; the fingerprint after the change has to equal the one before it. `unblock` of a blocked device removes the kept fingerprint, so the next operation takes the current state as the new reference; on a device that is not blocked it keeps the fingerprint and records no unblock; the first operation on a device takes it without a comparison.

## ExtremeXOS

The `ports` table has one object per physical port; a port without a display string is an object with no attributes, so the table offers only `update`. Its own configuration line is `configure ports <n> display-string <text>`; removal is `unconfigure ports <n> display-string`. Other lines that name the same port number, such as VLAN membership or `description-string`, belong to the rest of the configuration and are compared like any other line. A display string set on a port list is refused. The check account reads `show ports <n> information detail`, whose first line shows the string in parentheses.

For the `vlan-membership` and `ports` tables the write account also reads `show ports no-refresh` before planning and takes the port numbers of its `Port Summary` table as the ports of the switch; an answer without that table refuses the request. The configuration alone does not list them: a port that was never configured has no line in `show configuration`, and while the membership of the Default VLAN is unchanged the switch prints neither `configure vlan default delete ports all` nor a membership line of `Default`. In that state every listed port without another native VLAN is untagged in `Default`, and the planner, `verify`, the safeguard return, `recover` and the audit use that membership, so the inverse of a native move returns the port to `Default`. Once the configuration holds `configure vlan default delete ports all`, the membership of `Default` is explicit and a listed port without a native VLAN is refused. That line counts as membership, not as the rest of the configuration, and so do `configure vr VR-Default delete ports <ports>` and `configure vr VR-Default add ports <ports>` when they name exactly the listed ports: the first change of a port of a factory switch, a membership change or a display string, makes it print the explicit form, on the EXOS-VM image with the `delete` line, and the X440-G2 prints both lines in its explicit form. So the explicit form the switch prints after the first change of a port off the implicit `Default` is not a foreign change. With the port list, a display string compares the rest of the configuration through the same membership model, the membership of the port itself included; without it the lines are compared as before. The audit of a display string on such a port also sees its implicit `Default`. `doctor` reads the same port list and audits the configuration with that membership, so the number of audit findings it reports is the one `apply` starts from; before 0.2.6 it audited the configuration alone and counted `exos.management.port-native` for every never-configured port that the audit policy lists. The line `configure sys-recovery-level switch reset`, which the switch prints after the first change of a port and which states the default value, is left out of the comparison of every ExtremeXOS table; another recovery level and a VR port line with other ports are compared like any other line. The plan keeps the list as `ports`; a plan without it (0.2.4 and earlier, or FortiOS) is read as before. A port the switch does not list is refused with `port <n> is not reported by the switch`, for a display string too. A port named in `enable sharing <master> grouping <ports>` is refused with `VLAN membership changes on link aggregation ports are unsupported`, also when it has no VLAN line. The port list and the refusal of an unlisted port were measured on the EXOS-VM image and on the X440-G2, and the changes of never-configured ports on factory EXOS-VM images (see [Measured for 0.2.5](#measured-for-025-changes-by-someone-else-the-port-list-and-the-audit-export)). Not measured on a device: the first change of a factory X440-G2 or other hardware switch; a line other than those above that a switch adds when `Default` becomes explicit is compared like any other, so the change is returned as a foreign change and the device is blocked.

A membership line with `configure vlan <name> add ports all` or a range across slots such as `1:1-2:4` is expanded with the port list the snapshot itself carries: the union of the lists in `configure vr <name> add ports` and `configure vr <name> delete ports`, through `management.port_inventory()` and `management.exos_model()` of netops-auditor 0.2.9, the same expansion the auditor's rules use. Where the snapshot carries no such list, an end of a cross-slot range is not in it, or a membership line has neither `tagged` nor `untagged`, a `vlan-membership` or `ports` change is refused before any mutation with `VLAN membership cannot be evaluated from this snapshot`. For a `vlan` change such lines leave only the management rules `port-native` and `port-policy` `not-evaluated`, which that table does not require, and the change goes ahead.

The admin takes the state of every rule of the catalogue from the auditor (`rule_status` of netops-auditor 0.2.9) and confirms only a complete evaluation: every rule outside the management catalogue, the management rules named in `required_rules` of the operator policy and the management rules the table needs (`group-empty`, `group-dangling` and `group-cycle` for `firewall addrgrp`, `dhcp-conflict` and `dhcp-subnet` for DHCP reservations, `port-native` and `port-policy` for `vlan-membership`) must be `evaluated`; any other management rule that is not evaluated does not block. An incomplete evaluation of the snapshot before the change refuses the request with `the auditor evaluation is not complete: mandatory rules not evaluated: <rule> (<reason>), ...` (at most eight rules named). After the change the confirmation stops with the reason `audit incomplete`, the step `audit_incomplete` names the reasons, and the safeguard returns the change; the device is not blocked. A UPM profile without its closing `.` leaves the whole catalogue `not-evaluated` (`unterminated-upm-profile`), so it refuses the request before the change and stops the confirmation after it.

A FortiOS dump that ends inside a block or inside a quoted value, which the auditor parser reports as `TruncatedError`, is `snapshot incomplete`, the same as a dump cut at a section boundary. Before the change the request is refused with `snapshot is cut off: unterminated block opened at line <n>` (or `unterminated quoted value opened at line <n>`) and the device is not blocked. After the change the confirmation stops, the safeguard returns the change and the reason `snapshot incomplete` blocks the device; up to 0.2.4 a cut inside a section ended as `postcheck unavailable` without a block. Any other parse error of the dump stays `snapshot unreadable`, and a FortiOS snapshot with a `config global` or `config vdom` block after the change is `snapshot scope unsupported`.

The safeguard is a Universal Port Manager profile holding the planned inverse and a non-periodic UPM timer bound to it (`configure upm timer … after <seconds>`). The profile body is entered line by line after `create upm profile` and ends with a line holding a single dot. The script begins with `configure cli mode persistent` and `configure cli mode scripting ignore-error` so timer execution updates persistable membership and attempts the remaining inverse after a partially applied change. Read-back compares the profile contents with both prefixes and the inverse and requires the timer to be non-periodic with its next execution within 10 seconds of the planned moment. The names are `netops` + six hexadecimal characters of the operation + `p` or `t`: 13 characters, because `show upm timers` prints fixed-width columns and longer names run into each other. A fired one-shot timer stays in the configuration without a next execution and is removed like an unfired one.

The safeguard is part of the running configuration while it is installed; the snapshot comparison leaves out the profile body and the timer lines of these names, and any other UPM change counts as a change of the rest.

ExtremeXOS applies commands immediately but keeps them across a reboot only after `save configuration`, which asks `(y/N)`; the answer is sent as the next line. Before any change the admin opens a session and refuses when the prompt carries the unsaved-changes marker `*`, because saving would also store someone else's pending changes. It saves after a confirmation, after a verified return and after removing a safeguard that did not read back; it does not save after a foreign change it has detected. A confirmed change whose save failed is reported as `confirmed` with the reason `not persisted` and blocks the device.

`save configuration` stores the whole running configuration and cannot be tied to the snapshot the admin checked, so a change by someone else that lands between the last snapshot before the save and the end of the save is stored with it. The admin therefore takes one more snapshot after the save. When it differs from the prediction, the result is `confirmed` (the planned change was verified and the safeguard is gone) with the reason `foreign change during save` and the differences in the journal record, the audit log counts them, and the device is blocked: a person decides whether the stored foreign change stays. A snapshot that cannot be read after the save gives `confirmed` with the reason `saved configuration unverified` and also blocks the device. The window cannot be closed: a foreign change during the save is detected and reported, not prevented, and a change after the snapshot that follows the save is outside the operation, like any later change.

The account check compares the accounts in the snapshot (`create account`, `configure account`) with the list configured for the device. The configured firmware must equal the `ExtremeXOS version` reported by `show version`. Error answers start with `%%` on the lines after the echoed command; the echo itself is not searched, so a description containing such text is not mistaken for an error. The switch clock is read from `show switch`, because `show upm timers` prints the current time only while a timer exists.

## Results

| Result | Meaning |
|---|---|
| `rejected` | Nothing was changed on the device, the safeguard included. |
| `confirmed` | The predicted state was verified and the safeguard was removed. |
| `reverted` | The safeguard (or the removal of an unverified safeguard) returned the object to its previous state, verified by a snapshot. |
| `unknown` | The state could not be determined. |
| `revert-failed` | After the safeguard fired, the object is not in its previous state. |

`unknown`, `revert-failed`, a failed account check (another account list or changed account entries), a change made by someone else during the operation, a confirmed change that could not be saved and a save that could not be verified afterwards block the device. A snapshot after the change that is refused also blocks it; the reason names the cause: `administrator table` for the account check, `snapshot incomplete` (also a FortiOS dump cut inside a block or a quoted value), `snapshot scope unsupported`, `snapshot unreadable` or `snapshot firmware mismatch` for the snapshot itself, and `postcheck rejected` for any other refusal of the comparison. A blocked device refuses every request until `netops-admin unblock --reason …` is run by a person; the unblock is recorded in the audit log with the length of the reason.

`netops-admin apply` and `netops-admin undo` print the journal record and exit with `0` only for `confirmed` without a blocking reason. A `confirmed` result that blocked the device (reason `not persisted`, `foreign change during save` or `saved configuration unverified`) exits with `6`: the planned change is on the device, but the device refuses further changes until a person runs `unblock`. Every other result exits with `4`. `netops-admin recover` exits with `6` when any operation it settled left the device blocked (result `unknown` or `revert-failed`, or a blocking reason such as `foreign change`) and with `0` otherwise, also when there was nothing to settle. The other commands keep their codes: `1` a snapshot does not match the plan, `2` usage error, `3` request refused or preview not ready, `4` enrollment not valid, `5` doctor found the device not ready. The MCP tools do not return an exit code; `admin_apply` and `admin_status` carry `result` and `reason` as before.

A change by someone else is detected when the rest of the evaluated scope (the table on FortiOS, the whole configuration on ExtremeXOS) differs from the snapshot taken before the change. The operation is then not confirmed, the safeguard returns the planned object, and the result is `reverted` with the reason `foreign change`. This covers the snapshots after the change and the last snapshot before the safeguard is removed.

The removal of the safeguard cannot be atomic with that last snapshot. A change by someone else between the snapshot and the removal, or after the removal and before the next snapshot, leaves the planned change on the device without a safeguard: the admin does not save, reports `unknown` with the reason `foreign change after the safeguard was removed` and the differences, and blocks the device. When that snapshot instead shows the object in its previous state and the rest unchanged, the safeguard fired before it was removed, and the result is `reverted` with the reason `safeguard fired during confirmation`. A change by someone else during the save on ExtremeXOS is described in [ExtremeXOS](#extremexos).

## Interruption

The journal record stays `running` when the process is killed. A new request for the same device is refused until `netops-admin recover` settles it: with the safeguard still installed it waits for the safeguard and verifies the return; with the safeguard already gone it compares the device with both predictions and reports `confirmed` only when the interruption happened after confirmation began. An operation interrupted before its safeguard was planned is settled as `rejected` without contacting the device; when the device cannot be reached for any other, `recover` records the step `recovery_access_failed` and settles it as `unknown` with the reason `interrupted; device unreachable`, which blocks the device.

## Limits

Every limit is set by the administrator in the configuration; the agent cannot change any of them. A request whose `request_id` is already known returns its operation before any limit is checked.

| Limit | Default | Exhausted |
|---|---|---|
| request size, text lengths, attributes per request | 16384 bytes; key 128, reason 500, user request 4000 characters; 16 attributes | the request is refused |
| `plan_commands` | 32 commands in the plan and in the inverse | the request is refused before any mutation |
| `changes_per_device_per_hour` | 6 operations that reached the device | new changes on that device are refused |
| `changes_per_day` | 40 operations that reached a device | new changes are refused |
| `rejections_per_hour` | 30 refused requests | every new request is refused until the hour passes; a refused `apply` and a `preview` with the result `rejected`, a missing enrollment included, count alike; refusals by an exhausted budget are not counted; refusals of concurrent processes are counted under a lock, so none is lost; an unreadable `rejections.json` in `state_dir` refuses every request until a person checks it |
| `journal_records` | 20000 operations in the journal | new changes are refused until the journal is archived |
| `safeguard_seconds`, `confirm_margin_seconds` | 180 s, 45 s per device | bounds of the safeguard and of the time left for confirmation |
| export queue | 1000 events, 900 s oldest, status at most 120 s old | new changes are refused |

An exhausted limit never stops the return of an operation already started: waiting for the safeguard, `recover` and the notification of a result are not counted.

## Undo

`netops-admin undo --change-id <id> --reason <text>` is a command for a person. It accepts only an operation whose result is `confirmed`, derives the inverse request (delete for a create, create with the previous attributes for a delete, the previous values for an update) and runs it as a new operation through every gate, limit and safeguard, with `request_id` `undo-<change id>`. The new plan must find the object exactly in the state the original operation left it; if anything changed it since, the undo is refused instead of applying a blind inverse. Running the same undo again returns the operation it started.

## MCP

`python -m netops_admin.mcp_server` reads the configuration named by `NETOPS_ADMIN_CONFIG` and offers six tools. `admin_preview` takes the same fields as `admin_apply` and returns what `netops-admin preview` prints; `admin_doctor` takes a device and returns the report of `netops-admin doctor`. Both only read the device, and a `rejected` preview is counted in `rejections_per_hour`; like `admin_apply` they are refused while another operation of the same server runs. `admin_apply` takes the fields of a request plus `device` and returns the change identifier, the result, the reason, the differences (at most 20, as text read from the device), the names of the steps, the safeguard, the notification and the audit delivery; a refused request returns `rejected` with its reasons. `admin_status` returns the same view for a `change_id` or a `request_id`. Neither returns the reason or the user request. One server runs one operation at a time and refuses a second one while the first runs. When the client disconnects during an operation, the server finishes it before it exits.

## Audit log, export and notification

The audit log is JSON Lines with a closed set of fields per event: `start`, `step`, `result`, `delivery`, `administrative`. Free text is never copied: the request carries a reason and a user request, the log records their lengths; a text attribute is recorded as `text of N characters`. The file is created with mode 0640.

Export is the job of a standard log shipper; the component only reads a status file and enforces the limits (`export_max_pending`, `export_max_age_seconds`, `export_status_max_age_seconds`). A status that is stale, unreadable, over the pending limit or older than the age limit refuses new mutations before any change. `scripts/export_status.py` writes that file from the queue counter of a syslog-ng destination and is meant to run as root from a timer; if syslog-ng cannot be queried the file is not updated and becomes stale. Started with `--audit-file`, it names in the status the audit log the destination reads. A status that names another file than `audit_file` of the configuration counts as blocked with the reason `the export status covers another audit file`: it acknowledges nothing, refuses enrollment and new mutations, and `doctor` reports it as `refused`. A status without the name, from an exporter started without `--audit-file`, is accepted as before, and `doctor` adds `the export status does not name the audit file` to its `ok` line.

`audit_delivery` records what the shipper can tell: `pending` when the operation finished, `acknowledged` once a later status of the same audit file shows an empty queue, `blocked` when the limits were exceeded or the status covered another audit file. Nothing re-evaluates `pending` on its own: it stays until `netops-admin status` or the MCP tool `admin_status` reads the operation. That read is not a pure read: when it acknowledges the delivery it saves the journal record and writes a `delivery` event to the audit log. Acknowledged means that the shipper wrote the events to its transport, not that the receiver stored them.

The notification is sent to an ntfy topic read from a file at the moment of sending; the title is ASCII and the body carries the result, the operation, the identifiers and a count of differences, never free text. Its outcome is recorded separately from the result of the change. `netops-admin notify-retry --change-id …` sends it again and never touches the device. As long as the notification of a finished operation is `pending` or `failed`, no new change on that device starts; a successful `notify-retry` releases it, and a person who has checked the channel can run `unblock`, which marks such notifications `waived` and records one administrative event per operation. Before the safeguard is installed the tool counts the other administrator sessions on the device (FortiOS `get system admin list` without the accounts of the tool and the internal `Fortimanager_Access`; ExtremeXOS `show session` rows not marked as the own session) and records the count in the journal, the audit log and the notification; a session of another administrator does not stop the change. `x509_strict: false` in the notify configuration relaxes only the additional RFC 5280 checks Python applies by default, for a network whose TLS inspection authority does not mark its basic constraints critical; the chain is still verified.

## Data flow: what is read, kept, sent and printed

This section states where each piece of data goes. It is checked by `tests/test_privacy_canaries.py` (see the end of the section).

**Read from the device, kept only in memory.** Each operation reads the full configuration with the write account, which holds every secret of the device: FortiOS `set password ENC`, `set passwd ENC`, `set psksecret ENC`, `set secret ENC`, `set key ENC`, `set passphrase ENC`, certificate `private-key` blocks, SNMP community names; ExtremeXOS `create account … encrypted`, RADIUS and TACACS `shared-secret encrypted`, SNMP communities. On FortiOS it also reads `show system admin` with the password hashes of the accounts. The texts live in the process for the duration of the operation and are never written; the vault values (password, private key) are used only by netops-core to log in.

**Derived from the snapshot and kept.** Unsalted SHA-256 digests: `snapshot_sha256` of the whole snapshot, `rest_sha256` of the rest of the configuration (FortiOS certificate `password` and `private-key` and Wi-Fi `sae-password` ciphertexts replaced by a placeholder because FortiOS encrypts them anew on each export), the account fingerprint (FortiOS: the visible `system admin` entries with their password hashes and the referenced access profiles; ExtremeXOS: the `account` and `sshd2` lines with their encrypted hashes) and the auditor findings before the change (fingerprint, rule, severity and a digest of the evidence; the ExtremeXOS default-community rule names the object by a digest of the trivial community it found). A digest holds no secret, but it confirms a guess of its whole input; for the snapshot and the account table that input is not guessable. `request_sha256` is the digest of the whole request including `reason` and `user_request`.

**What can carry a value of the configuration.** Only the profile attributes of the one planned object: the planned commands, the inverse, the predicted object before and after the change (`predicted`) and the differences of a comparison (`comment: expected '…', found '…'`). No profile holds a secret: the supported attributes are `subnet` and `comment` (FortiOS address), `member` and `comment` (address group), `ip`, `mac` and `description` (DHCP reservation), `tag` and `description` (ExtremeXOS VLAN), `display-string` (port) and `tagged` and `untagged` (VLAN membership). An object that holds any other attribute, such as `passwd`, is refused before any change with `object '<key>' holds configuration outside the profile: passwd`; when such an attribute appears during the operation, the difference names it the same way. The name, never the value, is reported; the fixed attributes (`type`, `action`, `exclude`) are reported with their value.

**Sent to the device.** The planned commands, and the safeguard: on FortiOS an automation action whose `cli-script` is the inverse, a trigger and a stitch; on ExtremeXOS a UPM profile with the inverse and a timer. The safeguard holds the previous profile attributes of the object, for example the comment of an address being deleted, and stays in the device configuration until it is removed after the confirmation or the return.

**Journal** (`state_dir`, directories 0700, files 0600, read by the account that runs the tool and printed by `status`):

| File | Content | Removed |
|---|---|---|
| `operations/<change_id>.json` | identifiers, `request_sha256`, device, hostname, the plan (commands, inverse, predicted object, prechecks, digests, lengths of `reason` and `user_request`), steps (name, time and a short detail: an exception class name, a count or a fixed phrase), account fingerprint, auditor findings before, audit policy and coverage, the count of other sessions, result, reason, differences, `notification`, `audit_delivery` | never by the tool; `journal_records` refuses new changes once it is full |
| `requests/<request_id>.json` | request and change identifiers, `request_sha256`, device | never by the tool |
| `baselines/<device>.json` | account fingerprint | by `unblock` of a blocked device |
| `enrollments/<device>.json` | protocol, digest of the binding, firmware, change identifier, time | replaced by the next `enroll`, removed when it starts |
| `blocked/<device>.json` | reason, change identifier | by `unblock` |
| `rejections.json` | times of refused requests | entries older than an hour, at the next refusal |

Every file of the journal is read only as a regular file of at most 16 MiB and never through a symbolic link. A file that is not one JSON object, repeats a key within one object or holds a field of the wrong type is refused as `the state file <path> cannot be read; a person must check it`, and a journal directory the tool cannot use (a file, a pipe or a link loop in its place) as `the state directory cannot be used: <reason>`; the tool changes nothing until a person has looked at it. A lock file that is not a regular file is refused the same way.

**Audit log** (`audit_file`, 0640, shipped by the log shipper; how long the copy lives is set by the shipper and the collector). The closed field set of each event is listed above; `reason`, `user_request` and text attributes are recorded as lengths, a name list as a count, an address as `changed`, and an integer such as a VLAN tag as its value.

**Notification.** One HTTP `POST` to `<server>/<topic>`, the topic read from `topic_file` at the time of sending, for every finished operation and once more before the probe of `enroll` (result `enrollment-preflight`). Headers: `Title: netops-admin <device> <result>`, `Priority` (3 for `confirmed` and `rejected`, 5 for `unknown` and `revert-failed`, 4 otherwise), `Tags: netops`, and the standard headers of Python's HTTP client. Body, one item per line: `result: <result>`, `operation: <op> <table> <key>`, `change: <change_id>`, `request: <request_id>`, and when they apply `reason: <reason>` (a fixed phrase of the tool), `other administrator sessions were active: <n>`, `differences: <n>` and `the device is blocked until a person investigates it`. The device name, the operation and the key of the object are operational data that the operator of the ntfy server and every subscriber of the topic see; no attribute value, difference text, free text or secret is sent.

**Printed.** `plan`, `preview`, `apply`, `undo` and `status` print the plan or the journal record, including the predicted object and the differences; `verify` prints the differences. The MCP tools return the summary described in [MCP](#mcp), which carries the differences but no plan. Refusals name keys, attribute names and the values of profile attributes of the object; errors of the device access name the exception class or the message of the SSH layer and the collector, not a credential.

**Test.** `tests/test_privacy_canaries.py` puts a distinct synthetic secret into every place listed in the first paragraph, into the vault and into `reason` and `user_request`, runs `enroll`, `doctor`, `preview`, `apply` (create, update, delete, `undo`, a repeated request), refusals (referenced object, used name, protected key, blocked device, undelivered notification, unfinished operation, unreadable journal file, unreadable device, an attribute outside the profile), a refused line, a check-account mismatch, a prediction mismatch, a foreign value and a foreign secret attribute on the planned object (`revert-failed`), a failed and retried notification, `recover` after an interruption, `unblock`, `status`, the offline `plan` and `verify`, the MCP tools, and the real device access against a closed local port with a vault of mode 0600 and 0644. It then searches every output, stderr, every file in `state_dir`, the audit log, the export status and the notifications received by an HTTP server on 127.0.0.1 for each secret as text, as its last fragment, in hexadecimal, URL-encoded and in base64 at each of the three alignments. It also checks that no notification and no audit event carries a text attribute value, and the exact form of each notification.

## Write account on FortiOS

The safeguard needs the automation tables. On FortiOS 8.0.0 a restricted access profile reaches them only with `sysgrp` permission `admin read-write`; `cfg`, `mnt` and `upd` do not make them visible, `admin read` makes them readable only. With `admin read-write` the account sees in the administrator table only itself and accounts it created, cannot edit other accounts (`-37`) and cannot raise its own profile (`-672`), but it can create another administrator with its own profile. That is why step 4 and step 8 require that the write account sees exactly the configured accounts: an account it created is found before the next change and after the change that created it.

FortiOS shows the write account every administrator whose access profile is contained in its own, and lets it edit such an account (measured on 8.0.0: a comment of the check account changed and was restored). A read-only check account is therefore visible to the write account and has to be named in `accounts`; the fingerprint of the account entries detects a change of it, for example a replaced key, before the next change and during a change. Giving the check account a permission the write account lacks, such as `cli-diagnose`, hides it, but widens what the check account can do; the release does not do that.

Check account profile used in the lab: `fwgrp read`, `cli-get` and `cli-show` enabled, every other group `none`, trusted host limited to the admin host, key login.

Profile used in the lab: all groups `read`, `fwgrp custom` with `address read-write`, `sysgrp custom` with `admin`, `cfg`, `mnt`, `upd` `read-write`, `cli-get`, `cli-show`, `cli-config` enabled, `cli-exec` and `cli-diagnose` disabled, trusted host limited to the admin host. The account logs in with a key; its password is not given to the admin host.

## Measured on FortiOS

FortiGate 60F, FortiOS 8.0.0 build0167, one write account as above, from one admin host:

| Scenario | Result |
|---|---|
| create, update (text with a space), delete | `confirmed`, about 27 s each |
| same request again from a new process | the journal record is returned, the device is not contacted |
| another address changed by the same account during the change window | `reverted`, reason `foreign change`, device blocked |
| admin process killed with SIGKILL after the change was applied | journal `running`, new requests refused, `recover` → `reverted` |
| SSH client killed during the snapshot after the change | `reverted`, reason `postcheck unavailable` |
| write account created an extra administrator before the request | `rejected` before any mutation, device blocked |
| audit log not writable | `rejected` before any mutation |
| export status stale | `rejected` before any mutation |
| notification channel unreachable | `confirmed`, notification `failed`; `notify-retry` sent it without contacting the device |
| collector unreachable (TCP 601 rejected) | the change finished, `audit_delivery` `blocked`; the next request `rejected` with the queue over the limit; after the collector returned the queue drained |

Every scenario was checked against the device configuration, not against return codes; the configuration after all scenarios equals the one before them.

## Write account on ExtremeXOS

An `admin` account with a key bound by `create sshd2 user-key` and `configure sshd2 user-key … add user`; ExtremeXOS accepts only RSA user keys. The password hash given at creation is random with no known password, so the account logs in with the key only. An admin account can create other accounts; the account list check of step 3 and step 8 finds such an account before the next change and after the change that created it. The check account is a `user` level account with its own RSA key and no known password; it reads `show vlan` and is refused `show configuration` and every write.

## Measured on ExtremeXOS

Extreme X440-G2, ExtremeXOS 33.7.1.6, a VLAN without ports, the write account above, from one admin host, safeguard 180 s:

| Scenario | Result |
|---|---|
| create with tag and description, update of the description, removal of the description, delete | `confirmed`, about 39 s each, of which about 11 s is `save configuration`; the switch reported the new save time after each |
| create with a tag another VLAN uses | `rejected` by the plan, the switch not written |
| admin process killed with SIGKILL after the change was applied | `recover` waited for the timer, which ran the profile at the planned second (`show upm history` `Pass`), then verified the return, removed the safeguard and saved: `reverted` |
| unsaved change of another account on the switch | `rejected` before any mutation |

The configuration after all scenarios equals, byte for byte, the one saved before them.

Schema transactions use `admin_schema_preview` and `admin_schema_apply`,
with `device`, `operations`, `reason`, `user_request` and `request_id`.
Each operation supplies `path`, `scope`, `owners`, `op` and `changes`.
They share the same server lock and execution engine as profile requests.
The operation summary includes `budget_changes`, which counts every step.
The operator must bind the exact library and measured calibration to the
device and enroll the resulting configuration. See the [schema transaction
instructions](../README.md#schema-transaction-planning).
The check account needs read access to each operation's context and a
management interface belonging to an assigned VDOM. When switching contexts,
CLI configuration navigation must be allowed while its permission groups
remain read-only. Changes to this account or its profile require new enrollment.

## Measured: installation, MCP and undo

On an ARM64 Linux host with Python 3.13.15, from the three exported source trees: the lock installed with `--require-hashes`, the three components installed without dependency resolution, the tests (205) and the gate passed inside the unpacked `netops-admin` tree. Then, with an MCP client over stdio against the FortiGate 60F above:

| Scenario | Result |
|---|---|
| list of tools | `admin_apply`, `admin_status` |
| `admin_apply` create | `confirmed`, 39 s, the object present on the device |
| the same request again | the same operation, no new journal record, the device not contacted |
| `undo` of that operation | `confirmed`, 27 s, the object gone |
| client killed with SIGKILL right after the change started | the server finished the operation (`confirmed`) and exited 17 s later |
| request touching a protected object | `rejected`, no journal record |

The configuration after all scenarios equals the one before them.

## Measured: check account and auditor

With the check accounts above, over MCP from the installed tree, on the FortiGate 60F and the Extreme X440-G2:

| Scenario | Result |
|---|---|
| FortiOS create and update | `confirmed`, 34 s each; the steps show the auditor and the check account passed before the confirmation |
| FortiOS request with a check credential whose key the device does not accept | `rejected` before any mutation: the check account could not read the object |
| FortiOS check account comment changed by another administrator between two operations | `rejected` before any mutation, device blocked; still blocked after the comment was restored; after `unblock` the next change `confirmed` |
| ExtremeXOS create of a VLAN with a 32-character name and a 64-character description | `confirmed` and saved, 48 s; the check account read the full name and description |
| ExtremeXOS `undo` of that VLAN | `confirmed` and saved, 42 s |

The configurations after the scenarios equal the ones before them. On the FortiOS device two queries of the administrator table a few seconds apart gave the same fingerprint.

## Measured: notification wait, other sessions and the ports profile

| Scenario | Result |
|---|---|
| FortiOS change with an unreachable notification server | `confirmed`, notification `failed` |
| next change on the same device | `rejected` before any mutation: the notification was not delivered |
| `notify-retry` of that operation, then the change again | notification `sent`, change `confirmed` |
| FortiOS change while another administrator session was open, then after it was closed | `confirmed` with one other session recorded, then with none |
| older lab operations with undelivered notifications | refused new changes until a person ran `unblock`, which recorded one waiver per operation |
| ExtremeXOS display string, measured by hand before the profile was enabled | a one-shot UPM timer removed a string set after it and restored a string replaced after it, each at the planned second |
| ExtremeXOS display string set over MCP | `confirmed` and saved; the check account read the string |
| MCP server and client killed after the new string was written | `recover` waited for the timer, which restored the previous string: `reverted`, saved, 205 s |
| `undo` of the display string | `confirmed` and saved, the port without a string |
| display string on a protected uplink port, and a string made of digits | `rejected` before any mutation |
| FortiOS create and delete with `check_address` set to the second WAN address, SSH temporarily allowed there | both `confirmed`; a packet capture on the second WAN interface showed the SSH connections of the check account from the admin host |

The switch configuration after the port scenarios equals, byte for byte, the one before them.

## Measured on the ExtremeXOS 33.6.1.14 EXOS-VM image

EXOS-VM 33.6.1.14 is the virtual ExtremeXOS image Extreme publishes for labs, not a switch model: these measurements cover the CLI and the on-device UPM timer, not a forwarding plane. Before the three EXOS profiles were enabled on this build (0.2.4), the timer was measured by hand with the commands the planner emits for 33.7.1.6: a one-shot UPM timer 60 s ahead, the change applied after it, the result read by the check account.

| Scenario | Result |
|---|---|
| VLAN create with tag and description, description change, description removal, delete of a VLAN with a description | the timer restored the previous state 0–2 s after the planned second; the rest of the configuration unchanged |
| tagged add, tagged removal, native VLAN move, combined native and tagged change on one port | restored 1 s after the planned second |
| port display string set, replaced, removed | restored 0–1 s after the planned second |
| timer deleted before it fired | the change stayed |
| membership of a port that was never configured | refused by the planner, `object '5' does not exist`: on this image such a port has no line in `show configuration` (0.2.4; 0.2.5 reads the port list, see [ExtremeXOS](#extremexos)) |

Then, on 28 September 2026, with the 0.2.4 source tree, its own write and check accounts, an operator policy and a safeguard of 60 s:

| Scenario | Result |
|---|---|
| enrollment | probe returned by the timer, `reverted`, enrollment `valid`; a later change of the operator policy made `doctor` ask for a new enrollment, which passed the same way |
| VLAN create, description update and its `undo`, then `undo` of the create | `confirmed` each; the VLAN is gone |
| port display string set and its `undo` | `confirmed` |
| tagged membership added over the command line, removed over MCP | `confirmed`; `admin_status` by `request_id` returned the same operation |
| native VLAN move with the check account read lost after the change | returned by the timer: `reverted`, `check identity unavailable` |
| `Default` or `Mgmt` as the key | `rejected` before any mutation: protected |
| a membership outside the operator policy | `rejected`: `violates exos.management.port-policy` |
| a membership with the port rules of the operator policy missing | `rejected` before any mutation: `mandatory audit rules were not evaluated: port-policy` |
| unsaved change of another account on the switch | `rejected` before any mutation |
| released 0.2.3 against the same image | `doctor` not ready, all three tables `not measured on this firmware`; `preview` `rejected` |

Every operation's notification was sent. The switch configuration after the series equals the one before its first change, line for line.

## Measured on FortiOS 8.0.0 build0167: address group and DHCP reservation

On 29 September 2026, on a lab FortiGate 60F with FortiOS 8.0.0 build0167, the safeguard was first measured by hand in the form the admin installs (a one-shot automation stitch whose `cli-script` action holds the inverse): member additions and removals of a static address group, and a DHCP reservation create, update and delete, were all returned when the trigger fired, one transaction per `config ... end` block. The returned reservation kept its ID, a recreated group got a new UUID, and a stitch deleted before its time left the change in place, the same as on 7.6.7 build3704. Then, with the development branch of 0.2.5 and the instance's own write and check accounts:

| Scenario | Result |
|---|---|
| enrollment | the probe returned by the stitch (`reverted`), enrollment `valid` |
| address group member added over the command line and over MCP, each undone | `confirmed`, `undo` `confirmed` |
| member change with a lost check-account read, over the command line and over MCP | `reverted`, `check identity unavailable`, the device not blocked |
| a seventh change within one hour | `rejected`, the hourly budget exhausted, nothing written |
| DHCP reservation created over the command line, its description updated over MCP, deleted over the command line | `confirmed` each |
| reservation update with a lost check-account read | `reverted`, `check identity unavailable` |

Every notification was sent. The DHCP runs needed the `netgrp` permissions listed in [installation](installation.md#write-account-on-the-device), granted for the test and removed afterwards; without `netgrp read` the check account cannot read the DHCP server (`Command fail. Return code -61`) and the admin refuses the request before any change. Address group create and delete are not enabled by the profile and were measured by hand only. Other FortiOS 8.0 builds stay refused for both tables.

## Measured for 0.2.5: changes by someone else, the port list and the audit export

On 29 September 2026, before the release, with the 0.2.5 source as it stood before its last change (the exit code `6` of `recover` and one definition of the blocking results and reasons, run afterwards with the release archive, see the end of this section), the instances' own write and check accounts, and a change by someone else sent at a chosen step of the operation: by another administrator account on the EXOS-VM image and on the FortiGate, by a separate session of the write account on the X440-G2. The foreign change was a port display string on ExtremeXOS and the comment of an unrelated test address on FortiOS, never the planned object.

| Scenario | EXOS-VM 33.6.1.14 | X440-G2, ExtremeXOS 33.7.1.6 | FortiGate 60F, FortiOS 8.0.0 build0167 |
|---|---|---|---|
| change without a foreign change | `confirmed`, exit `0`, saved | `confirmed`, exit `0`, and its `undo` | `confirmed`, exit `0`; no step after a save, FortiOS does not save separately |
| foreign change after the check-account read, before the last snapshot with the safeguard installed | `reverted`, `foreign change`, exit `4`, device blocked; the planned VLAN gone, the foreign change kept, nothing saved | `reverted`, `foreign change`, exit `4`, device blocked; the planned port returned | `reverted`, `foreign change`, exit `4`, device blocked; the planned address gone, the foreign comment kept |
| foreign change after the removal of the safeguard | `unknown`, `foreign change after the safeguard was removed`, exit `4`, device blocked; the planned VLAN and the foreign change left unsaved | not run | `unknown`, the same reason, exit `4`, device blocked; the planned address and the foreign comment left |
| foreign change between the last check and `save configuration` | `confirmed`, `foreign change during save`, exit `6`, device blocked; the save stored both changes | `confirmed`, `foreign change during save`, exit `6`, device blocked; the differences name the foreign change | does not apply |
| process killed with SIGKILL after the change, then a foreign change, then `recover` | `recover` waited for the timer: `reverted`, `foreign change`, device blocked, nothing saved; this source still exited with `0` | not run | not run |
| `preview` of a membership and of a display string on a port the switch does not list | `rejected`, `port <n> is not reported by the switch` (ports 13 and 99 of a 12-port image) | `rejected`, the same for port 99 | does not apply |
| `preview` of a listed port | `ready` | `ready` | does not apply |

After each blocking case the test removed the foreign change and the planned object where it stayed, ran `unblock`, and `doctor` reported the device ready. The configuration after each series equals the one before it; on FortiOS except the configuration version counter and one value FortiOS encrypts anew on every export.

The same day `scripts/export_status.py` of the 0.2.5 source ran on the audit host of the test installation from its timer with `--audit-file` naming the audit log that the syslog-ng destination reads, checked in the syslog-ng configuration; the status carried `audit_file`. The released 0.2.4 ignored the new field: `doctor` ready, audit export `ok acknowledged`. With the 0.2.5 source the instance whose `audit_file` is that log reported `ok acknowledged` without the note, and `status` moved its pending operation to `acknowledged`. A second instance with another audit log and the same status file was refused with `the export status covers another audit file`, and its pending operation stayed `pending`.

After the release build, the 0.2.5 source archive itself, installed with Auditor 0.2.8 and Core 0.2.5 from their release archives as the installation guide describes, ran on 29 September 2026 against the EXOS-VM image with a copy of the lab instance: `doctor` reported the enrollment missing and `apply` was refused until `enroll` passed; a display-string change and its `undo` ended `confirmed` with exit `0`; a process killed after the change, followed by a change by someone else, left `recover` with `reverted`, `foreign change`, the device blocked and exit `6` (without the foreign change `reverted`, `interrupted` and exit `0`); an `undo` with a change by someone else during `save configuration` ended `confirmed`, `foreign change during save`, the device blocked and exit `6`. The audit export status of that copy was written by hand, not by the exporter, and the configuration after the run matched the one before it.

Factory switches, the same day: a release candidate built before the change that counts the VR-Default lines as membership and leaves out the default recovery level ran on a factory EXOS-VM 33.6.1.14 image (`Config Booted: Factory Default`, no membership line in `show configuration`). Enrollment, `doctor` and a VLAN create passed; a tagged addition on a never-configured port was returned by the safeguard as `reverted`, `foreign change`, exit `4`, device blocked, because the first membership change added `configure vr VR-Default delete ports 1-12` and `configure sys-recovery-level switch reset` besides the explicit `Default`. After the change, on two new factory images of the same build: a tagged addition on a never-configured port, its `undo`, a native move of another never-configured port and its `undo` ended `confirmed` with exit `0`, each saved, and `doctor` then reported the device ready; on the second image a native move of a never-configured port killed with SIGKILL after the change was returned by the timer and `recover` settled it as `reverted`, `interrupted`, without differences, saved, the device not blocked. A display string on a never-configured port that the audit policy lists was then refused by the audit, and once the audit saw the implicit `Default` the switch printed the explicit form after the display string itself and the change was returned as a foreign change; after both were changed, on a third new image a display string on such a port, its `undo`, a tagged addition on another never-configured port and its `undo` ended `confirmed` with exit `0`, and `doctor` then reported the device ready.

## Not measured, or known limits


- The fingerprint of the administrator accounts includes their access profiles. A fingerprint recorded while a profile carried temporary permissions no longer matches once they are removed, and the next `doctor`, `preview` or `apply` refuses the device with `the administrator accounts changed since the last operation`. Measured on 26 September 2026 on FortiOS 7.6.7: compare the profiles and entries with a snapshot from the time of the fingerprint, and only when the difference is the reverted permission run `unblock` with that reason; the accounts check then records the current state. Do not change permissions while an operation is running.
- For 0.2.3 the DHCP reservation profile on FortiOS and the write profiles on ExtremeXOS were not run again on a device; the release changes only the access path, which the FortiOS address and group operations and the read-only EXOS checks of 26 September 2026 exercised.
- The branch that refuses to confirm when too little time is left before the safeguard fires is covered by tests only: on the lab firewall the whole sequence took about 10 s and on the switch about 15 s until the confirmation, so even the shortest allowed safeguard (60 s) left enough time.
- On ExtremeXOS the account check, a safeguard that does not read back and a failed save are covered by tests only; a foreign change during the confirmation was run for 0.2.5 (see [above](#measured-for-025-changes-by-someone-else-the-port-list-and-the-audit-export)); `undo` was run on the X440-G2 for 0.2.0 and 0.2.5 and on the EXOS-VM image for 0.2.4.
- For 0.2.4 the ExtremeXOS profiles on the X440-G2 (33.7.1.6) and the FortiOS profiles were not run again with the release source; the release changes only the list of measured EXOS builds. On the EXOS-VM image SIGKILL with `recover`, a foreign change during the window and a failed save were not run.
- For 0.2.5 the exit code `6` of `apply` and the ExtremeXOS port list were run on the EXOS-VM image and on the X440-G2 in the lab before the release; the exit code `6` of `recover` and of `undo` were run with the release archive on the EXOS-VM image, and a `confirmed` result with the reasons `not persisted` or `saved configuration unverified` is covered by tests only. A foreign change after the removal of the safeguard was not run on the X440-G2, and `recover` after a killed process only on the EXOS-VM image.
- The limits of the table in [Limits](#limits) are covered by tests only; none was exhausted on a device.
- A new auditor finding after a change is covered by tests only, with the real rules of the auditor on a fixture: the supported tables do not reach any rule of the auditor, and a change elsewhere in the configuration is already refused as a change outside the planned object.
- Without `check_address` the check account reads the object over the same management path as the write account; it proves another identity, not another path. The check reads the configuration, not whether the traffic behaves as intended.
- The auditor step records how many rules it evaluated. For the supported tables none of the rules can report a finding; a meaningful auditor gate needs rules about those tables, which is work on the auditor, not on this component.
- With the collector reached over TCP, syslog-ng lost one event that was on the way when the connection was reset, although its destination has a reliable disk buffer; `processed` and `written` differed by one and nothing was counted as queued or dropped. The local audit log is complete and remains the record; the remote copy can miss an event.
- Each query opens its own SSH connection, about a dozen per operation.
- The name check of the planner leaves out the FortiOS attributes and ExtremeXOS commands that [planning](planning.md#names-and-references) lists as secrets or free text, and its refusals do not say where a name was found. A plaintext secret in an attribute or a command outside those lists still counts as a name, so a refusal still confirms a guess of it; every such refusal, of `preview` as of `apply`, counts against `rejections_per_hour`. The auditor applies the same list: from `netops-auditor` 0.2.9, which this release pins, the FortiOS rule `fortios.management.address-unused` counts an address as used only when its name appears in an attribute outside that list, so the `audit_findings_before` that `preview` reports no longer changes when a secret or a comment equals the name of an otherwise unreferenced address.
