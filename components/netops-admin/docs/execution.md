# Execution: safeguard, journal, audit and what is measured

`netops-admin apply` executes one planned change on one configured device, FortiOS or ExtremeXOS. This page describes the sequence, the safeguard of each platform, where it was measured and what it does not guarantee.

## Sequence

1. Take the device lock; refuse a `request_id` already used for different content, a blocked device, and a device with an unfinished operation.
2. Check that the journal and the local audit log can be written durably and that the audit export is not blocked.
3. Read, with the write account, a full configuration snapshot (collected by the netops-auditor collector, host key pinned) and check the accounts (see the platform sections).
4. Refuse when the account check fails (the device is also blocked, see below), when a safeguard of an earlier operation is still installed, or when a platform precheck fails.
5. Plan the change (see [planning.md](planning.md)) and require a valid device enrollment. Audit the before and predicted snapshots against the operator policy and require the selected operation's mandatory rule coverage and let the check account read the object; refuse when the auditor cannot evaluate or when the check account cannot read the object or sees it in another state than the snapshot. Write the journal record and the start event of the audit log, both synced to disk, before the first mutation.
6. Install the safeguard: a one-shot object on the device that runs the planned inverse a configured number of seconds after the device clock. Read it back and compare it with the plan; a safeguard that does not read back is removed and nothing else is done.
7. Apply the planned commands line by line over an interactive session and stop at the first line the device refuses.
8. Take a new snapshot, check the accounts again and compare the snapshot with the prediction: the object and the rest of the evaluated scope. Let the auditor evaluate the new snapshot: a new or changed finding of severity high or medium, or an evaluation that does not complete, stops the confirmation. Let the check account read the object: it has to see exactly the predicted state.
9. Confirm only when everything matches and enough time is left before the safeguard fires: remove the safeguard, read back that it is gone, verify the object once more and, where the platform needs it, save the configuration.
10. Otherwise do not confirm: wait until the safeguard has fired, take a snapshot, verify that the object is back to its previous state, remove the safeguard and, where the platform needs it, save the configuration.

## FortiOS

The safeguard is a one-shot automation stitch whose `cli-script` action is the planned inverse. The inverse script is written with real newlines inside the quoted `set script` value; quotes and backslashes inside it are escaped. `set trigger-datetime` takes the date and time as two unquoted tokens. The account check requires that the write account sees in the administrator table exactly the configured accounts (by default only itself). FortiOS applies configuration immediately and keeps it; nothing is saved separately.

## Accounts and the check account

Every device has two accounts of the tool: the write account and a read-only check account. The check account reads the object before the change and after it (`show firewall address "<key>"` on FortiOS, `show vlan <key>` on ExtremeXOS); it cannot write, and its key is a separate credential. With `check_address` it connects to another management address of the device than the write account, so the check also takes another path; the host key is checked against the same pin. On ExtremeXOS the answer of the switch carries a non-zero exit status also when the query succeeds, so only a recognised answer counts: the object shown, or the message that no VLAN of that name exists. A VLAN without a description shows `None`; the profile refuses that word as a description.

The account check computes a fingerprint of the account entries (on FortiOS the entries the write account sees in `show system admin` together with their referenced access-profile permissions, on ExtremeXOS the `account` and `sshd2 user-key` lines of the snapshot) and keeps it after each operation that starts. A later operation refuses and blocks the device when the fingerprint differs; the fingerprint after the change has to equal the one before it. `unblock` removes the kept fingerprint, so the next operation takes the current state as the new reference; the first operation on a device takes it without a comparison.

## ExtremeXOS

The `ports` table has one object per physical port; a port without a display string is an object with no attributes, so the table offers only `update`. Its own configuration line is `configure ports <n> display-string <text>`; removal is `unconfigure ports <n> display-string`. Other lines that name the same port number, such as VLAN membership or `description-string`, belong to the rest of the configuration and are compared like any other line. A display string set on a port list is refused. The check account reads `show ports <n> information detail`, whose first line shows the string in parentheses.

The safeguard is a Universal Port Manager profile holding the planned inverse and a non-periodic UPM timer bound to it (`configure upm timer … after <seconds>`). The profile body is entered line by line after `create upm profile` and ends with a line holding a single dot. The script begins with `configure cli mode persistent` and `configure cli mode scripting ignore-error` so timer execution updates persistable membership and attempts the remaining inverse after a partially applied change. Read-back compares the profile contents with both prefixes and the inverse and requires the timer to be non-periodic with its next execution within 10 seconds of the planned moment. The names are `netops` + six hexadecimal characters of the operation + `p` or `t`: 13 characters, because `show upm timers` prints fixed-width columns and longer names run into each other. A fired one-shot timer stays in the configuration without a next execution and is removed like an unfired one.

The safeguard is part of the running configuration while it is installed; the snapshot comparison leaves out the profile body and the timer lines of these names, and any other UPM change counts as a change of the rest.

ExtremeXOS applies commands immediately but keeps them across a reboot only after `save configuration`, which asks `(y/N)`; the answer is sent as the next line. Before any change the admin opens a session and refuses when the prompt carries the unsaved-changes marker `*`, because saving would also store someone else's pending changes. It saves after a confirmation, after a verified return and after removing a safeguard that did not read back; it does not save after a foreign change. A confirmed change whose save failed is reported as `confirmed` with the reason `not persisted` and blocks the device.

The account check compares the accounts in the snapshot (`create account`, `configure account`) with the list configured for the device. The configured firmware must equal the `ExtremeXOS version` reported by `show version`. Error answers start with `%%` on the lines after the echoed command; the echo itself is not searched, so a description containing such text is not mistaken for an error. The switch clock is read from `show switch`, because `show upm timers` prints the current time only while a timer exists.

## Results

| Result | Meaning |
|---|---|
| `rejected` | Nothing was changed on the device, the safeguard included. |
| `confirmed` | The predicted state was verified and the safeguard was removed. |
| `reverted` | The safeguard (or the removal of an unverified safeguard) returned the object to its previous state, verified by a snapshot. |
| `unknown` | The state could not be determined. |
| `revert-failed` | After the safeguard fired, the object is not in its previous state. |

`unknown`, `revert-failed`, a failed account check (another account list or changed account entries), a change made by someone else during the operation and a confirmed change that could not be saved block the device. A blocked device refuses every request until `netops-admin unblock --reason …` is run by a person; the unblock is recorded in the audit log with the length of the reason.

A change by someone else is detected when the rest of the evaluated scope (the table on FortiOS, the whole configuration on ExtremeXOS) differs from the snapshot taken before the change. The operation is then not confirmed, the safeguard returns the planned object, and the result is `reverted` with the reason `foreign change`.

## Interruption

The journal record stays `running` when the process is killed. A new request for the same device is refused until `netops-admin recover` settles it: with the safeguard still installed it waits for the safeguard and verifies the return; with the safeguard already gone it compares the device with both predictions and reports `confirmed` only when the interruption happened after confirmation began.

## Limits

Every limit is set by the administrator in the configuration; the agent cannot change any of them. A request whose `request_id` is already known returns its operation before any limit is checked.

| Limit | Default | Exhausted |
|---|---|---|
| request size, text lengths, attributes per request | 16384 bytes; key 128, reason 500, user request 4000 characters; 16 attributes | the request is refused |
| `plan_commands` | 32 commands in the plan and in the inverse | the request is refused before any mutation |
| `changes_per_device_per_hour` | 6 operations that reached the device | new changes on that device are refused |
| `changes_per_day` | 40 operations that reached a device | new changes are refused |
| `rejections_per_hour` | 30 refused requests | every new request is refused until the hour passes; refusals by an exhausted budget are not counted |
| `journal_records` | 20000 operations in the journal | new changes are refused until the journal is archived |
| `safeguard_seconds`, `confirm_margin_seconds` | 180 s, 45 s per device | bounds of the safeguard and of the time left for confirmation |
| export queue | 1000 events, 900 s oldest, status at most 120 s old | new changes are refused |

An exhausted limit never stops the return of an operation already started: waiting for the safeguard, `recover` and the notification of a result are not counted.

## Undo

`netops-admin undo --change-id <id> --reason <text>` is a command for a person. It accepts only an operation whose result is `confirmed`, derives the inverse request (delete for a create, create with the previous attributes for a delete, the previous values for an update) and runs it as a new operation through every gate, limit and safeguard, with `request_id` `undo-<change id>`. The new plan must find the object exactly in the state the original operation left it; if anything changed it since, the undo is refused instead of applying a blind inverse. Running the same undo again returns the operation it started.

## MCP

`python -m netops_admin.mcp_server` reads the configuration named by `NETOPS_ADMIN_CONFIG` and offers four tools. `admin_preview` takes the same fields as `admin_apply` and returns what `netops-admin preview` prints; `admin_doctor` takes a device and returns the report of `netops-admin doctor`. Both only read; like `admin_apply` they are refused while another operation of the same server runs. `admin_apply` takes the fields of a request plus `device` and returns the change identifier, the result, the reason, the differences (at most 20, as text read from the device), the names of the steps, the safeguard, the notification and the audit delivery; a refused request returns `rejected` with its reasons. `admin_status` returns the same view for a `change_id` or a `request_id`. Neither returns the reason or the user request. One server runs one operation at a time and refuses a second one while the first runs. When the client disconnects during an operation, the server finishes it before it exits.

## Audit log, export and notification

The audit log is JSON Lines with a closed set of fields per event: `start`, `step`, `result`, `delivery`, `administrative`. Free text is never copied: the request carries a reason and a user request, the log records their lengths; a text attribute is recorded as `text of N characters`. The file is created with mode 0640.

Export is the job of a standard log shipper; the component only reads a status file and enforces the limits (`export_max_pending`, `export_max_age_seconds`, `export_status_max_age_seconds`). A status that is stale, unreadable, over the pending limit or older than the age limit refuses new mutations before any change. `scripts/export_status.py` writes that file from the queue counter of a syslog-ng destination and is meant to run as root from a timer; if syslog-ng cannot be queried the file is not updated and becomes stale.

`audit_delivery` records what the shipper can tell: `pending` when the operation finished, `acknowledged` once a later status shows an empty queue (`netops-admin status` re-evaluates it), `blocked` when the limits were exceeded. Acknowledged means that the shipper wrote the events to its transport, not that the receiver stored them.

The notification is sent to an ntfy topic read from a file at the moment of sending; the title is ASCII and the body carries the result, the operation, the identifiers and a count of differences, never free text. Its outcome is recorded separately from the result of the change. `netops-admin notify-retry --change-id …` sends it again and never touches the device. As long as the notification of a finished operation is `pending` or `failed`, no new change on that device starts; a successful `notify-retry` releases it, and a person who has checked the channel can run `unblock`, which marks such notifications `waived` and records one administrative event per operation. Before the safeguard is installed the tool counts the other administrator sessions on the device (FortiOS `get system admin list` without the accounts of the tool and the internal `Fortimanager_Access`; ExtremeXOS `show session` rows not marked as the own session) and records the count in the journal, the audit log and the notification; a session of another administrator does not stop the change. `x509_strict: false` in the notify configuration relaxes only the additional RFC 5280 checks Python applies by default, for a network whose TLS inspection authority does not mark its basic constraints critical; the chain is still verified.

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

## Not measured, or known limits

- The fingerprint of the administrator accounts includes their access profiles. A fingerprint recorded while a profile carried temporary permissions no longer matches once they are removed, and the next `doctor`, `preview` or `apply` refuses the device with `the administrator accounts changed since the last operation`. Measured on 26 September 2026 on FortiOS 7.6.7: compare the profiles and entries with a snapshot from the time of the fingerprint, and only when the difference is the reverted permission run `unblock` with that reason; the accounts check then records the current state. Do not change permissions while an operation is running.
- For 0.2.3 the DHCP reservation profile on FortiOS and the write profiles on ExtremeXOS were not run again on a device; the release changes only the access path, which the FortiOS address and group operations and the read-only EXOS checks of 26 September 2026 exercised.
- The branch that refuses to confirm when too little time is left before the safeguard fires is covered by tests only: on the lab firewall the whole sequence took about 10 s and on the switch about 15 s until the confirmation, so even the shortest allowed safeguard (60 s) left enough time.
- On ExtremeXOS the account check, a foreign change during the window, a safeguard that does not read back, a failed save and `undo` are covered by tests only.
- The limits of the table in [Limits](#limits) are covered by tests only; none was exhausted on a device.
- A new auditor finding after a change is covered by tests only, with the real rules of the auditor on a fixture: the supported tables do not reach any rule of the auditor, and a change elsewhere in the configuration is already refused as a change outside the planned object.
- Without `check_address` the check account reads the object over the same management path as the write account; it proves another identity, not another path. The check reads the configuration, not whether the traffic behaves as intended.
- The auditor step records how many rules it evaluated. For the supported tables none of the rules can report a finding; a meaningful auditor gate needs rules about those tables, which is work on the auditor, not on this component.
- With the collector reached over TCP, syslog-ng lost one event that was on the way when the connection was reset, although its destination has a reliable disk buffer; `processed` and `written` differed by one and nothing was counted as queued or dropped. The local audit log is complete and remains the record; the remote copy can miss an event.
- Each query opens its own SSH connection, about a dozen per operation.
