# Admin configuration in NetOps 1.0

Configure the stopped instance using a private JSON file (mode 0600) outside the source checkout. Input requires `config` and `vault`. The optional `notification_topic` is required on the first notification setup: 8–64 ASCII letters, digits, underscores or hyphens. Never send this file, topic or credentials to MCP or logs.

The adapter validates input, fixes state/audit/topic/device-vault paths inside the Admin private directory and stores the topic in mode 0600. An arbitrary path does not import host files. Reconfiguration preserves the topic when omitted. Credentials remain separate from Helper and Auditor.

## Complete input example

The document is schema-valid; every address, pin, account, credential and notification endpoint/topic is a placeholder. Replace them using trusted device identity and reviewed permissions before enrollment. Validation does not contact a device or send a notification.

```json
{
  "config": {
    "version": 1,
    "notify": {
      "server": "https://ntfy.example.invalid",
      "timeout_seconds": 10
    },
    "limits": {
      "changes_per_device_per_hour": 6,
      "changes_per_day": 40
    },
    "devices": {
      "firewall-a": {
        "platform": "fortios",
        "address": "192.0.2.10",
        "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "credential": "firewall-write",
        "check_credential": "firewall-check",
        "accounts": [
          "example-write",
          "example-check"
        ],
        "safeguard_seconds": 180,
        "confirm_margin_seconds": 45,
        "protected": {
          "firewall address": [
            "all",
            "none"
          ]
        }
      }
    }
  },
  "vault": {
    "version": 2,
    "credentials": {
      "firewall-write": {
        "kind": "password",
        "login": "example-write",
        "value": "replace-with-write-secret"
      },
      "firewall-check": {
        "kind": "password",
        "login": "example-check",
        "value": "replace-with-check-secret"
      }
    }
  },
  "notification_topic": "replace_with_private_topic"
}
```

```sh
docker compose stop
docker compose run -T --rm netops configure admin < admin-private.json
docker compose up -d --wait
```

Until this configuration is saved, the MCP Admin tools return `admin_not_configured`, whose hint means this `configure admin` command with the private JSON on standard input, and an offline command such as `admin status` refuses with `configuration: devices must be a non-empty object`, because init stores an Admin configuration without devices.

## Enroll the device and verify readiness

Configuration alone does not authorize changes. First verify the configured device host-key fingerprint through a trusted device console, the write/check account permissions and successful trusted-HTTPS notification delivery. Subscribe to the private notification topic before testing.

Enrollment performs a real temporary device change and deliberately lets the on-device safeguard return it; the exception is FortiADC, which has no on-device safeguard and returns the probe by compensation in the same run (see [FortiADC pool member](#fortiadc-pool-member)). Reserve a genuinely unused subnet for the FortiOS probe; the documentation subnet below is only an example and must be reviewed for the target. Enrollment can take the full safeguard interval and verification time. Keep this operator command running until it reports a final outcome.

~~~sh
docker compose stop
docker compose run --rm netops admin enroll --device firewall-a --probe 192.0.2.252/30
docker compose run --rm netops admin doctor --device firewall-a
docker compose up -d --wait
~~~

Successful enrollment reports `"enrollment": "valid"` with `"result": "reverted"` and reason `"enrollment self-test"`: the probe must be gone, the safeguard absent and notification sent. Doctor then reports `"ready": true`. An exit code alone is insufficient; inspect the structured result. If enrollment is not valid or doctor is not ready, stop and resolve the reported cause before requesting a change. Re-enroll after changing the bound device configuration, firmware, account identities, profiles or notification settings.

Doctor also checks whether the write and check accounts have more rights than their role needs. Each account reads only its own entry with `show system admin "<login>"` and, for the check account, its own profile with `show system accprofile "<profile>"`; doctor keeps only the profile fields and never reports password, `ENC` or certificate lines. The checks `write account rights` and `check account rights` report `warning` for a FortiOS `super_admin` or `prof_admin` write account before 8.0.1 (on 8.0.1 and later the webhook safeguard needs `super_admin`), for a FortiOS check account with `super_admin`, `prof_admin`, a `read-write` group or `cli-config enable`, and for a FortiADC check account with `is-system-admin yes` or a `read-write` area; a FortiADC write account may be a system administrator, which the health precheck of a pool member status change (`diagnose server-load-balance vs_stat`) and `pool-member` need. The warning names the row of [Accounts and least privilege](../components/netops-helper/docs/read-only-accounts.md) that lists the rights of that role; the FortiADC row `Admin check` there is not measured, so for a FortiADC check account the warning rests only on the entry and profile the account reads. They report `cannot verify` with the reason or the exact device answer when the entry or the profile cannot be read, for example a wildcard, RADIUS, TACACS+ or VDOM administrator without a local profile (an entry that is not found), a check account without `cli-show` (`Unknown action 0`), a `custom` group, or a profile the account does not see; a refusal line that may hold a secret is reported without the rest of the line. Neither status changes `ready` or the exit code. Since 1.0.10 doctor runs the full report on FortiADC too (before, it refused with `platform 'fortiadc' has no plan and apply adapter` and listed only the credentials and the two rights checks); its `audit policy` check is `cannot verify` there, because Admin runs no auditor rules on FortiADC (see [FortiADC pool member](#fortiadc-pool-member)). The `warning` and `cannot verify` results are verified by tests against simulated devices; on real devices (FortiOS 7.6.8, FortiOS 8.0.2, FortiADC 7.6.7) only the result `ok` was verified.

## Preview and make one explicit change

Use the authenticated HTTPS MCP connection from the [quickstart](quickstart-1.0.md). The request below creates an address object only; it does not add a traffic policy. Use a new object name and a reviewed unused subnet on an isolated test device for the first operation. Replace `user_request` with the actual words of the person authorizing that change, and choose a unique `request_id` (8–64 supported characters).

Call `admin_preview` with these arguments:

~~~json
{
  "device": "firewall-a",
  "table": "firewall address",
  "op": "create",
  "key": "netops-example-address",
  "changes": {
    "subnet": "192.0.2.248/30"
  },
  "reason": "Verify an explicitly authorized address object",
  "user_request": "Create this test address object on firewall-a.",
  "request_id": "example-address-create-0001"
}
~~~

Preview reads the device and returns the proposed commands, prediction and refusal reasons without making a change. Continue only when `result` is `ready` and the person has reviewed the plan. Then call `admin_apply` with the same arguments. Apply plans again from a fresh snapshot and uses the device safeguard and independent check account; preview is not a stored executable plan. On FortiADC there is no device safeguard: apply returns an unverified change by compensation in the same run, and after a loss of the Admin process `admin recover` returns it (see [FortiADC pool member](#fortiadc-pool-member)).

`admin_doctor`, `admin_preview`, `admin_apply` and the operator commands `admin doctor` and `admin enroll` read the device configuration over SSH with a 180-second limit that includes the host-key check (later SSH queries are limited to 60 seconds and interactive logins to 30 seconds). When the device does not answer, these calls return their refusal only after about 180 seconds. Set the request timeout of the MCP client above 180 seconds. A client timeout does not prove that the call was cancelled: the operation can still complete, and the audit can hold its response or an interrupted or pending record. Inspect `admin_status` and the actual device first, and never repeat a write automatically. The Admin worker handles one MCP request at a time; further Admin calls wait until the running one ends. While a long operator command such as `admin enroll` runs, `docker ps` can show its `docker compose run` container as `unhealthy`: the service healthcheck also runs in that container, which has no gateway (see the [quickstart](quickstart-1.0.md)). This does not affect the command; judge it by its final structured result.

A completed change must report `result: confirmed`, successful notification and no blocking reason. Retain the returned `change_id` and read it through `admin_status` using `{"change_id": "CHANGE_ID_FROM_RESPONSE"}`. Inspect the actual object through the independent read-only account. Repeating an already used `request_id` returns its existing operation; it does not authorize another write. For an unknown or interrupted result, inspect status and the actual device before any operator recovery.

## Return the test change as an operator

Undo is an explicit operator action, not an MCP tool. The MCP tool `admin_undo_preview` and the operator command `admin undo --preview` only show what the undo would do and change nothing (see [MCP tools](#mcp-tools)). Use the actual change ID from the confirmed operation:

~~~sh
docker compose stop
docker compose run --rm netops admin undo --change-id CHANGE_ID_FROM_RESPONSE --reason "Remove the verified test object"
docker compose run --rm netops admin status --change-id CHANGE_ID_FROM_UNDO_RESPONSE
docker compose up -d --wait
~~~

Undo creates a new safeguarded operation with its own change ID. Require its confirmed result, notification and independent verification that the object returned to its original state. Keep both operation records and the gateway audit. Never delete the state volume to clear a refusal or an unknown operation.

## Interrupted or unknown Admin operation

Stopping or restarting NetOps does not prove that an in-flight change was cancelled. The on-device safeguard can continue after the container exits. Do not repeat an unknown write automatically or delete its journal to remove a refusal.

Retain the original business request_id and change_id. Inspect admin_status and the actual device through the independent read-only account. The gateway audit pending command identifies requests without a trustworthy completed response; a pending entry alone does not tell you whether the device changed.

For explicit operator recovery, stop the instance and use the original request ID and configured device alias:

~~~sh
docker compose stop
docker compose run --rm netops audit pending
docker compose run --rm netops admin status --request-id REQUEST_ID_FROM_ORIGINAL_ARGUMENTS
docker compose run --rm netops admin recover --device firewall-a
~~~

Recovery can inspect and settle the existing operation using its saved safeguard and original state. Inspect every returned settled record, notification result and the actual device; an exit code alone is insufficient. A still-running or blocked operation requires investigation before any new write. After the original operation is settled, start the instance with docker compose up -d --wait. A subsequent write requires a new explicit request and a new request_id.

Available operator recovery commands and flags can be inspected while the instance is stopped:

~~~sh
docker compose stop
docker compose run --rm netops admin --help
docker compose up -d --wait
~~~

Admin write and independent check accounts must differ (see the [device account model](account-model.md); the measured access profiles are in [Accounts and least privilege](../components/netops-helper/docs/read-only-accounts.md)). The check account verifies device identity and readback independently. FortiOS administrator visibility is bounded by the enrolled accounts. ExtremeXOS also needs exact `firmware` and the explicit create/configure account fingerprint; implicit accounts are not proven.

## Blocked device or undelivered notification

Admin blocks a device when an operation ends with result `unknown` or `revert-failed`, or with a blocking reason: `administrator table`, `foreign change`, `not persisted`, `foreign change during save`, `saved configuration unverified`, `postcheck rejected`, `snapshot incomplete`, `snapshot scope unsupported`, `snapshot unreadable` or `snapshot firmware mismatch`. Every further preview, apply or enrollment for that device is then refused with `the device is blocked (REASON, operation CHANGE_ID); a person must investigate and unblock it`, and doctor reports the device state as refused. A finished operation whose notification is still `pending`, `failed` or `sending` also refuses new operations on its device: `the notification of operation CHANGE_ID was not delivered; run notify-retry, or a person unblocks the device after checking the notification channel`.

These operator commands run with the instance stopped, like `recover` above:

- `admin notify-retry --change-id CHANGE_ID` sends the notification of that finished operation again unless it was already sent; it needs a configured notification.
- `admin unblock --device firewall-a --reason "TEXT"` is for a person who has inspected the operation record and the actual device. It lifts the block, clears the stored administrator-account baseline of the device and marks its undelivered notifications as `waived`. The private Admin operation log records only the length of the reason, not its text. The command prints a JSON object with `device` and `unblocked`, which is `false` when there was nothing to lift or waive.

On FortiOS, a result `unknown` whose `steps` in `admin_status` end with `safeguard_kept` means that NetOps could prove neither that its timed safeguard fired nor that it was disarmed, so it left the safeguard on the device. The safeguard is three automation objects named after the first 12 characters of the change ID: the stitch `netops-sg-ID12-s`, the trigger `netops-sg-ID12-t` and the action `netops-sg-ID12-a`, where the action holds the inverse CLI script and the trigger is scheduled once at `safeguard.fire_at`. A stitch that fires late can still restore the previous object after you inspected it, so before `unblock` check for these objects through an administrator account (`show system automation-stitch netops-sg-ID12-s`, and likewise `automation-trigger` and `automation-action`) and remove them before you judge the object. Delete the stitch first, because it refers to the trigger and the action; on a device with VDOMs, run the commands inside `config global`:

~~~
config system automation-stitch
delete "netops-sg-ID12-s"
end
config system automation-trigger
delete "netops-sg-ID12-t"
end
config system automation-action
delete "netops-sg-ID12-a"
end
~~~

Then read the object again, compare it with the operation record and unblock the device only after that.

NetOps 1.0 reads no firing record from FortiOS. After an expired safeguard it waits until `safeguard.fire_at` plus 20 seconds, reads the configuration and ends with `unknown` and `safeguard_kept` when the object is not the previous one and the stitch `netops-sg-ID12-s` still exists. A once trigger stays configured after it has fired, so `safeguard_kept` does not mean that the stitch did not fire. The device itself shows whether it fired, through an administrator account:

~~~
diagnose test application autod 3
~~~

lists every stitch; for `netops-sg-ID12-s`, a stitch that fired shows `local hit` of at least 1, the time in `last trigger` and `next scheduled trigger:trigger expired`. The event log records each firing:

~~~
execute log filter reset
execute log filter category event
execute log filter field logid 0100046600
execute log display
~~~

Each firing is one line with `logid="0100046600"`, `logdesc="Automation stitch triggered"` and `stitch="netops-sg-ID12-s"`. Such a line proves that the stitch was triggered, not that its inverse script restored the object; compare the object as above either way. In a measurement of 21 once triggers, 10 on a FortiGate 80F with FortiOS 8.0.2 build0251 and 11 on a FortiGate 60F with FortiOS 7.6.7 build3704, each trigger fired between 0.1 and 5 seconds after its `trigger-datetime`, within the 20 seconds that NetOps waits.

Inside NetOps, the operator commands `apply`, `preview`, `doctor`, `enroll`, `status`, `recover`, `notify-retry`, `unblock`, `undo`, `pool-member`, `pool-member-add` and `pool-member-remove` receive `--config` with the private Admin configuration automatically; `admin enroll --help` and the other subcommand help pages still list `--config` as required, but the documented commands omit it. `plan`, `verify`, `schema-plan` and `schema-verify` are offline engine commands that take explicit file paths readable by the Admin UID, and `apply` and `preview` also need a `--request` file. NetOps 1.0 places Admin operator files only through `configure admin` (JSON on standard input), so these engine commands have no supported way to receive their input files and are not a supported operator workflow in NetOps 1.0; preview and apply changes with the MCP tools `admin_preview` and `admin_apply`.

## Webhook safeguard on FortiOS 8.0.1 and later

A Fortinet Technical Tip states that from FortiOS 8.0.1 build0185 the auto-script engine allows only `get` and `diagnose` commands, and on 8.0.2 build0251 the `cli-script` safeguard was observed to refuse every configuration line, so Admin does not use it to restore configuration from 8.0.1 ([verified support](verified-support.md#admin-safeguard-on-fortios-76-and-80)). On those builds Admin installs a webhook safeguard instead; the choice follows the snapshot firmware and needs no setting. The stitch calls the REST API of the same FortiGate with a temporary API user and sends the inverse request: `DELETE` for a create, `PUT` with the previous values for an update, `POST` with the previous object for the undo of a policy create. The full design is in the [webhook safeguard contract](fortios-webhook-safeguard-contract.md).

`admin doctor` reports these conditions, except the table and the request body, in its check `webhook safeguard` with the same texts; on firmware before 8.0.1 the check reports that the webhook is not used. Before any device write Admin refuses the request, naming the missing condition, unless:

- the device `address` in the Admin configuration is an IPv4 address, held by an interface in the snapshot, and that interface has `https` in `allowaccess` (the webhook calls this address on the `admin-sport` of `system global`, read with `show system global` before the API user is created, 443 when the answer omits it; a port that cannot be read refuses the request);
- the write credential is a password credential, because `execute api-user generate-key` asks for the administrator password;
- the write account has the access profile `super_admin` (read from its `system admin` entry in the snapshot), because only `super_admin` may create the API user of the safeguard;
- no `system api-user` or `system accprofile` named `netops-sg-…` is left from an earlier operation;
- the table has a REST inverse (`system dhcp server/reserved-address` has none, so it is refused on these builds) and the request body fits 1023 bytes.

On these builds the write account must therefore be a `super_admin` account; see [what to check](#write-account-for-the-webhook-safeguard-what-to-check). Schema transactions are not available on these builds.

The Auditor reports each of these objects left on a device as `fortios.mgmt.netops-safeguard-leftover` (severity high, remediation `admin recover`); during its own operation Admin ignores only its own safeguard. The safeguard is five objects named after the first 12 characters of the change ID: the access profile `netops-sg-ID12-p` (`fwgrp read-write`, everything else `none`), the API user `netops-sg-ID12-u` (that profile, trusthost the device address /32), the action `netops-sg-ID12-a` (`webhook`), the trigger `netops-sg-ID12-t` and the stitch `netops-sg-ID12-s`. Admin removes all five after confirmation and after expiry and proves their absence by reading back. When firing is not proven (`safeguard_kept`), Admin still deletes the API user and the access profile, so the token is revoked (step `safeguard_token_revoked`, or `safeguard_token_revoke_unverified` when the readback does not prove it), and leaves the stitch, trigger and action for the investigation above. `admin recover` deletes the API user and the access profile as well.

Cleanup after a partial installation: when the device refuses or ends the installation part-way, Admin removes what it created in the same operation and ends `reverted` with `safeguard not verified`. When that removal is not proven by the readback, the operation ends `unknown` with `safeguard not verified`, blocks the device and leaves objects such as the access profile `netops-sg-ID12-p`; `admin doctor` then names them (`a safeguard of an earlier operation is still installed: netops-sg-ID12-p`). Stop the instance and run `admin recover --device firewall-a`: for the operation that blocks the device, if it ended this way before `change_start`, recover deletes the remaining `netops-sg-ID12-…` objects of its change ID, reads them back and appends the step `safeguard_removed` (`safeguard_removal_unverified` when an object is still found; run `admin recover` again after the cause is fixed). The result stays `unknown` and the device stays blocked; read the steps with `admin status`, then run `admin unblock`. No manual CLI is needed for this case.

If NetOps stops during the window and is not recovered, remove the objects through an administrator account, the stitch first; on a device with VDOMs inside `config global` (on FortiOS 8.0.2 `delete` of the API user asks `Please enter current administrator password:`; enter the password of the signed-in administrator):

~~~
config system automation-stitch
delete "netops-sg-ID12-s"
end
config system automation-trigger
delete "netops-sg-ID12-t"
end
config system automation-action
delete "netops-sg-ID12-a"
end
config system api-user
delete "netops-sg-ID12-u"
end
config system accprofile
delete "netops-sg-ID12-p"
end
~~~

Residual risk: FortiOS keeps the `Authorization` header of the automation action in clear text in the configuration while the safeguard exists, so configuration backups taken during the window hold the API token. FortiOS also writes the header into the event log when the action is created (log ID 0100044547); the token therefore reaches syslog and FortiAnalyzer when logs are forwarded. Deleting the action does not remove it from those logs; NetOps neither disables logging nor deletes logs. The token is limited: it is accepted only from the device's own management address (trusthost /32), it carries `fwgrp read-write` and nothing else, and it is revoked when NetOps deletes the API user after confirmation, after expiry or in `admin recover`. `fwgrp read-write` is the whole firewall permission group, not one policy: whoever holds the token on the device itself can change any firewall object until it is revoked. If NetOps stops during the window, the token stays valid until `admin recover` or the manual cleanup above. NetOps never writes the token into the plan, the preview, the operation record, the Admin audit log, a notification or an error text, and Helper `config_read` hides the header value.

### Write account for the webhook safeguard: what to check

Measured on 2026-11-01 on FortiOS 8.0.2 build0251 (FortiGate 80F, active-passive HA). The device behaviour below is what the device answered; where it differs from a Fortinet document, the device is right.

- **Access profile `super_admin`.** Only `super_admin` may create the API user of the safeguard. Signed in with any other access profile, `config system api-user` answers `command parse error before 'api-user'` and `Command fail. Return code 1`; this stays so with `sysgrp read-write`, with every permission group `read-write` and with `cli-exec enable`. A restricted account also cannot create an access profile with more rights than its own: the safeguard profile (`fwgrp read-write`) is refused at its `next` with `object set operator error, -672 discard the setting` and `Command fail. Return code -672`. On FortiOS 8.0.1 and later the write account therefore needs the `super_admin` profile. `super_admin` has full rights on the device, so use a dedicated account for NetOps only, limit it with a trusted host /32 to the address the Admin host connects from, and keep its password only in the Admin credential store.

  1. An administrator with the `super_admin` profile creates or changes the account:

     ~~~
     config system admin
         edit "<write account>"
             set accprofile "super_admin"
             set trusthost1 <Admin host address> 255.255.255.255
             set password <password>
         next
     end
     ~~~

     `set password` is needed when the account is new (`edit` answers `new entry '<write account>' added`); leave it out for an existing account. On FortiOS 8.0.2 the device asks `Please enter current administrator password:` after `set password` and again after `next`; enter the password of the administrator who is signed in.
  2. Check it with `show system admin | grep "edit \|set accprofile\|set trusthost"`; under `edit "<write account>"` the answer lists `set trusthost1 <address> <mask>` and `set accprofile "super_admin"`.
  3. Run `admin doctor`. Until the account has `super_admin`, it reports the check `webhook safeguard` as `refused` with `the webhook safeguard needs the write account <login> with access profile super_admin on FortiOS 8.0.1 and later (only super_admin may create the API user of the safeguard); <login> has access profile <profile>`, and `admin preview`, `admin apply` and `admin enroll` refuse with the same text before any device write. When the device refuses a line while the safeguard is installed, the step `safeguard_not_verified` names the line, the object and the device answer, for example `safeguard installation failed (AccessError: line 13 (config system accprofile, edit "netops-sg-ID12-p") was refused by the device: object set operator error, -672 discard the setting | Command fail. Return code -672)`.
- **All administrators in `accounts`.** A `super_admin` write account sees every administrator of the device, so `accounts` in the device section must list all of them, as `show system admin | grep edit` lists them through a `super_admin` account. Otherwise the `admin doctor` check `administrator accounts` is `refused` and `admin preview`, `admin apply` and `admin enroll` refuse before any device write with a text that names the administrators the write account sees but `accounts` does not list (`not configured`) and the ones `accounts` lists but the device does not show (`not visible`), for example `the write account sees other administrators than the configured ones: not configured: admin, operator-1, netops-ro; not visible: netops-missing`. The built-in profile `super_admin` is not listed in `show system accprofile`; Admin accepts it without its profile text. Every other access profile of a visible administrator must be in the snapshot, otherwise the refusal names it: `an administrator access profile is not visible in the snapshot: <profile>`.
- **Password credential.** A write credential with an SSH key only is refused on 8.0.1 and later with `the webhook safeguard needs a password write credential: FortiOS asks for the administrator password when it generates the API key`, in the `admin doctor` check `webhook safeguard` and before any device write in `admin preview`, `admin apply` and `admin enroll`. Store a password credential for the write account. This is an accepted limitation of NetOps 1.0.5. FortiOS 7.6 with the `cli-script` safeguard is not affected.
- **What a restricted account sees.** A profile that is not `super_admin` does not list `super_admin` in `show system accprofile`, and in `system admin` and `system api-user` it lists only the entries its profile covers; the output does not say that anything is left out ([account model](account-model.md)). On 8.0.2 build0251 a read-only account listed in `show system accprofile` its own profile and one other read-only profile, but not the profiles with write rights, and in `show system admin` only itself (measured on 2026-11-02).
- **Password prompt for the API user.** On FortiOS 8.0.2 build0251 with a `super_admin` write account the device asks `Please enter current administrator password:` after the `next` that saves `system api-user "netops-sg-ID12-u"` and after `delete "netops-sg-ID12-u"`; the other lines of the installation and removal (access profile, trusthost entry, action, trigger, stitch) are answered with the prompt. Admin answers this prompt with the password of the write credential, and only when the device asks. Measured on 2026-11-02 without an answer: the device ends the SSH session about 9 seconds after the prompt, and the API user is saved all the same (`show system api-user netops-sg-ID12-u` lists it afterwards). A development build that did not answer it ended `admin enroll --probe` with `unknown` and `safeguard installation failed (AccessError: interactive session failed after 23 lines: the session to <address> ended before any of the 2 awaited pattern(s) matched, 86 byte(s) seen)` and left the access profile `netops-sg-ID12-p`.
- **Trigger readback.** `show system automation-trigger "<name>"` prints `set trigger-type scheduled` for the safeguard trigger on 8.0.2 build0251 and on 7.6.8 build3744, so Admin reads the trigger without `full-configuration`.

## Opt-in table `firewall policy`

`firewall policy` is off unless the device lists it: `"opt_in": ["firewall policy"]` in the device section (FortiOS only, `protected["system interface"]` must be non-empty). The change is bound into the enrollment, so run `admin enroll` again after changing `opt_in` and after upgrading.

- `create` is accepted only with `status disable`; the new policy is placed after all existing policies and is enabled by a separate `update` of `status` alone.
- `action deny` needs `logtraffic` in the same request: FortiOS 7.6.8 sets `logtraffic disable` with `action deny`, which the postcheck would find as a difference and the audit reports as `fortios.policy.logging-disabled`; send `logtraffic all`. `undo` of such an update brings `logtraffic` back as well.
- `update` of anything else uses the normal path; `undo` of a create deletes the policy, `undo` of an update restores the previous values (default values for attributes that were unset).
- The plan is refused when the policy id exceeds the limit, names an interface, address, service or schedule missing from the snapshot, touches the management path of a protected interface (also through `any`, zones or SD-WAN zones), or the inverse would not fit the safeguard script. Undo by delete is refused when the created policy is no longer the last policy, because the recreated policy would be appended at the end and change the policy order. This applies to both safeguards, also on FortiOS 7.6.8 with `cli-script`: once another policy has been added after the NetOps policy, remove it through the normal administration instead.
- The profile lists FortiOS 7.6.8 build3744 with the `cli-script` safeguard and 8.0.2 build0251 with the webhook safeguard ([Webhook safeguard on FortiOS 8.0.1 and later](#webhook-safeguard-on-fortios-801-and-later)); every other build, also 8.0.0 build0167 and 7.6.7 build3704, is refused before any device write. The defaults of FortiOS 7.6.8 are `status enable`, `logtraffic utm` and `action deny`, and `unset status` returns `enable`; the id limit 4294967294 and the script limit 1023 come from the FortiOS 7.6.8 CLI Reference. On 8.0.2 build0251 with a `super_admin` write account the full `admin apply` path was measured on 2026-11-02 on a FortiGate 80F active-passive HA pair with the webhook safeguard: `admin enroll --probe` ended `reverted`; create, update and undo of a policy ended `confirmed`; loss of the check account after the change ended `reverted` for an update (`PUT`), a create (`DELETE`) and an undo of a create (`POST`), each after `trigger-datetime`; SIGKILL after `change_applied` followed by `admin recover` ended `reverted`; the precheck refused a policy on the protected interface. No `netops-sg-` object stayed, the HA pair was in sync and the configuration after cleanup equalled the configuration before. A policy that names a member of an aggregate interface (for example `a` or `b` of the FortiLink aggregate `fortilink`) passes the precheck, because the member is an interface in the snapshot, but the device refuses the line `set dstintf`; Admin then ends `reverted` with `change failed` (step `change_failed`, detail `AccessError after 4 lines`) and the configuration stays unchanged. Name the aggregate, a VLAN or a zone instead. Zone members were not measured; a policy line that the device refuses ends the same way, with the configuration unchanged.
- **Undo limits.** `admin undo` runs once per change, under the fixed request ID `undo-CHANGE_ID`, so repeating it never repeats the write. Repeating exactly the same undo request (same reason) returns the stored result of the first undo. An undo of the same change with a different request (another reason) is refused with exit code 3 (rejected, like every refused request) and the text `undo of this change has already been performed; after a reverted change remove the object with regular administration`; nothing is sent to the device. Development builds printed `request_id was already used for a different request`, which says nothing about the cause. When the undo ended `reverted` (the safeguard restored the object), the object is still there and cannot be undone again; the profile has no `delete` operation, so remove such a policy through the normal administration. A genuine reuse of a request ID by another request keeps the text `request_id was already used for a different request`. `admin undo --preview` (MCP `admin_undo_preview`) runs every check of the undo, including the `delete` of an undo of a create, without any change; after an undo has run, also one with the same reason, it refuses with `undo_already_done`.
- **Provisional profile.** The profile `firewall policy` is provisional. Create and undo of a policy were measured on FortiOS 7.6.8 build3744 and 8.0.2 build0251, and the cleanup was verified (configuration equal to the configuration before, HA pair in sync, `admin recover` found nothing). On 8.0.2 the run with the whole management path blocked was recorded only once, with NetOps reaching the device through a translated (DNAT) address, and its repeat was not completed.
- **What was measured and what was only tested.** Measured live: on FortiOS 8.0.2 build0251 (FortiGate 80F active-passive HA pair, 2026-11-02) the main path `admin apply` with confirmation and revert, the attacks that remove the check account (`PUT`, `DELETE` and `POST` inverses), SIGKILL after `change_applied` followed by `admin recover`, and the precheck refusal; on FortiOS 7.6.8 build3744 (FortiGate 60F, `cli-script` safeguard) enrollment, a create and its undo. Verified only by automated tests against a simulated device, not on a real device: recovery after a partial installation of the safeguard (status `finished` with result `unknown` and `safeguard not verified`) through `admin recover`. Treat this recovery as untested on hardware and read the steps of `admin status` and the device afterwards.
- When the check account loses the device after the change, the safeguard restores the previous policy at `trigger-datetime` and the result is `reverted`; after a crash of NetOps after `change_applied`, `admin recover` ends `reverted`; when the whole management path is lost after the change, the result is `unknown` and the device stays blocked until the `netops-sg-` objects are removed and `admin unblock` runs. The measurements are in [verified support](verified-support.md#fortios-bounds).
- A Fortinet Technical Tip states that from FortiOS 8.0.1 build0185 auto-script, which the safeguard's `cli-script` action runs, allows only information-gathering commands (get, diagnose), while the 8.0.2 Administration Guide still shows CLI script examples with configuration commands. On a FortiGate 80F with 8.0.2 build0251 the stitch fired, but every configuration line was refused with `Unknown action or command is unavailable in auto-script`, and the probe address was still present after `trigger-datetime`. This is an observed refusal on the measured build and the statement of the Technical Tip, not a measurement of every 8.0.x build, so Admin does not rely on the `cli-script` safeguard from 8.0.1; on these builds Admin uses the webhook safeguard ([Admin safeguard on FortiOS 7.6 and 8.0](verified-support.md#admin-safeguard-on-fortios-76-and-80), with the Fortinet sources).

## Opt-in table `firewall service custom` (measured end-to-end)

**Measured end-to-end on FortiOS 7.6.8 build3744 and 8.0.2 build0251 (2026-11-14, tasks 168, 177 and 180).** The profile has `provisional: false`, `measured: true` and `exact_versions: true`; preview, apply and undo are available with the table enabled in `opt_in`.

`firewall service custom` holds custom TCP/UDP services, for example `TCP-8443` with `tcp-portrange 8443`. It is off unless the device lists it: `"opt_in": ["firewall service custom"]` in the device section (FortiOS only). The change is bound into the enrollment, so run `admin enroll` again after changing `opt_in`. Turning a policy on or off is not part of this table; it stays an `update` of `status` in [`firewall policy`](#opt-in-table-firewall-policy).

- Operations `create`, `update` and `delete`; `undo` of a create deletes the service, `undo` of a delete recreates it (with a new `uuid`), `undo` of an update restores the previous values. Attributes: `tcp-portrange`, `udp-portrange` (each one range `low[-high][:low[-high]]`, ports 1–65535, low ≤ high; a list of several ranges is refused) and `comment` (at most 255 characters). A service needs `tcp-portrange` or `udp-portrange`. The protocol stays `TCP/UDP/UDP-Lite/SCTP`. Shared defaults measured on both builds (empty category/fqdn, helper auto, check-reset-range default, color and timers 0, fabric-object disable, iprange 0.0.0.0, unset UDP-Lite/SCTP ranges) are normalized; nondefault fixed values and unsupported attributes are refused. Missing and empty `comment` are equivalent; CLI `unset comment` and REST `PUT {"comment":""}` restore that default. `visibility` and `proxy` are not shared fixed defaults.
- A service referenced in the configuration (for example by the `service` of a policy or by a service group) cannot be deleted, and its port ranges cannot change; its `comment` can. The predefined FortiOS services (`ALL`, `ALL_TCP`, `ALL_UDP`, `ALL_ICMP`, `HTTP`, `HTTPS`, `SSH`, `DNS`, `PING` and the other predefined names) are protected keys; names listed in `protected["firewall service custom"]` are protected as well.
- On FortiOS 8.0.1 and later the webhook safeguard calls `api/v2/cmdb/firewall.service/custom[/<name>]` (`DELETE` for a create, `PUT` for an update, `POST` with `name` for a delete); the earlier tables keep their REST paths `firewall/policy`, `firewall/address` and `firewall/addrgrp`.
- **Measured on the two exact builds above** (2026-11-14, CLI/REST and end-to-end Admin measurements). Preview/apply/undo succeeded with cli-script on 7.6.8 and webhook on 8.0.2 HA; loss of the check account reverted create and update. Referenced service delete/port changes and protected HTTPS changes were refused before writes. Not measured: safeguard firing a POST inverse, SIGKILL with admin recover, loss of the whole management path for this table, and comment/port-range length limits.

## ExtremeXOS port admin state and PoE cycle

Both operations are gated to ExtremeXOS 33.7.1.6 (patch level and model are not checked); measured only on 33.7.1.6-patch1-11 on X435-8P-4S/X440G2-12p-10G4 (write account with the R/W role; 2026-11-14, tasks 171 and 184). Other firmware version tokens are refused (`port_action_not_measured`; the port display string keeps its wider scope, including EXOS-VM 33.6.1.14).

**Port admin state.** The `ports` table has the attribute `admin-state` (`enabled` or `disabled`, default `enabled`). `admin preview`/`admin apply` (CLI and MCP `admin_preview`/`admin_apply`) with `{"table": "ports", "op": "update", "key": "8", "changes": {"admin-state": "disabled"}}` sends `disable ports 8`; `enabled` sends `enable ports 8`. The timed UPM safeguard holds the inverse after `configure cli mode persistent` (without it the switch restored the port, but `show configuration` kept `disable port 8`). The read-back is `show configuration` (a disabled port is the line `disable port 8` in module vlan) and, with the check account, `Admin state` of `show ports 8 information detail`; preview also shows the port and link state of `show ports 8 configuration no-refresh`. `admin undo` returns the previous state. A snapshot with `disable port N` was earlier a line outside the port object; it is now the `admin-state` of that port, also for display-string changes.

Before the admin state of a port is changed (disabled or enabled) Admin refuses, before any write:

| Code | Refused port |
|---|---|
| `port_protected` | listed in `protected["ports"]` of the device |
| `port_management_vlan` | member of a VLAN named in `management_vlans` of the device audit policy |
| `port_uplink` | carries tagged VLANs (a trunk is treated as an uplink) |
| `port_lag_member` | member of a link aggregation (`enable sharing`) |
| `port_lldp_neighbor` | has a neighbor in `show lldp neighbors` |
| `port_learned_mac` | has a learned address in `show fdb` |
| `port_usage_unreadable` | the LLDP or FDB answer is not recognised or incomplete (the FDB row count must match its `Total` line) |

Enabling a port gets the same checks and reads LLDP and FDB as disabling it does (since 1.0.10: enabling a disabled uplink or LAG member can bring back a loop); a display string change does not. The out-of-band management port is not a numbered port and cannot be named.

**PoE cycle.** With the instance stopped, `docker compose run --rm netops admin poe-cycle --config /var/lib/netops/admin/config.json --device sw-x435 --port 3 --reason "..." --user-request "..." --request-id ...` (with `--preview` it only checks) power-cycles one port: `disable inline-power ports 3`, then `enable inline-power ports 3`. `poe-cycle` is not among the operator commands that receive `--config` automatically, so the command names the private Admin configuration of the default state path itself. There is no MCP tool for it in 1.0.9. It runs through the same admission as `admin apply` (enrollment, budgets, blocking, operations log, notification) as one operation of kind `poe-cycle` on the table `inline-power`, behind the safeguard `enable inline-power ports 3`. That table cannot be changed by `admin_apply`/`admin_preview` (`action_only_table`); `admin doctor` lists it with the operation `poe-cycle`. The cycle:

1. reads `show inline-power info ports 3` (write account) and `show inline-power info detail ports 3` (check account);
2. reads the switch clock and checks that the time left until the safeguard fires is more than the cycle budget plus `confirm_margin_seconds` (see **Safeguard margin** below); otherwise it removes the safeguard, saves the configuration and ends `rejected` with `safeguard_margin_insufficient` without touching inline power;
3. disables inline power and verifies `show configuration` (the line `disable inline-power ports 3` in module poe) and the audit;
4. reads the check account every 2 s until it sees `Configured Admin State: disabled` and `Inline Power State: disabled`, for at most 15 s of pauses between the reads; it stops at the first read that shows both; when the pauses run out, the time of each read (up to 60 s) comes on top, so the wait can exceed 15 s (measured on 2026-11-14, task 171: about 1 s of `searching` first);
5. enables inline power and verifies that `show configuration` equals the state before;
6. reads the check account in the same way, for at most 60 s of pauses plus the time of the reads (with 31 reads of 2 s each about 122 s), until it sees `enabled` and a state other than `disabled`; when the port was `delivering` before, it waits for `delivering`;
7. removes the safeguard and saves the configuration.

The result is `confirmed`; when a powered device that was `delivering` is not `delivering` again by the end of the wait in step 6, it is `confirmed` with the reason `powered device not delivering after the cycle` (CLI exit code 4). The record holds `poe.before`, `poe.off` and `poe.after`. A cycle that fails or loses a read-back is settled by the safeguard as any other change (`reverted`, `unknown` or `revert-failed`). A PoE cycle has no undo (`undo_not_applicable`).

**Safeguard margin.** From the clock check in step 2 until the safeguard is removed in step 7 a cycle can take up to 175 s. This is a budget, not a measured duration: three writes (disable, enable, safeguard removal), two `show configuration` reads, the off wait (15 s of pauses and 9 reads) and the on wait (60 s of pauses and 31 reads). A read is budgeted at 2 s and `show configuration` at 4 s, the longest durations of task 171 (ssh exec, 1 s resolution). An interactive write was not timed on its own and is budgeted as two reads (4 s). A cycle without a powered device usually ends much sooner. The budget counts with response times as measured; a device that answers far slower than that (reads close to their timeouts) can exceed it, and then the safeguard decides: it restores the inline power configuration at its time, and the result is `unknown` or `reverted`, not an unsafe state. The cycle and `confirm_margin_seconds` must fit inside `safeguard_seconds`. When `175 + confirm_margin_seconds >= safeguard_seconds`, preview and apply refuse the PoE cycle with `safeguard_margin_insufficient` before any device read or write, without an operation record. `reason_details` gives `cycle_seconds`, `confirm_margin_seconds`, `available_seconds` and `required_safeguard_seconds`. With the default `safeguard_seconds` 180 and `confirm_margin_seconds` 45 a PoE cycle is refused: set `safeguard_seconds` of a switch used for PoE cycles to at least 221 (with the margin 45). Step 2 repeats the comparison against the switch clock after the safeguard is installed, because the installation itself takes time. When that check refuses, the operation ends `rejected` with the same code (CLI exit code 4) and inline power was not touched. When the clock cannot be read there, the code is `device_clock_unreadable`. In both cases the safeguard is removed and the configuration saved; if the removal is not proven the result is `unknown`, and if the save fails the reason is `not persisted` and the device is blocked.

**Interrupted cycle.** `admin recover` settles a cycle interrupted before `confirm_start` through the safeguard like any other change (`reverted` with the reason `interrupted`). After `confirm_start`, power was already seen on again. If the safeguard is already absent, recover ends `confirmed` with `confirmed before the interruption`, as in 1.0.9. If the safeguard is still installed, recover reports the cycle as done only on proof, which needs all three of these:

- the journal holds `poe_off_observed`, `poe_enable_verified`, `poe_on_observed` and `confirm_start` in this order, with `poe.off` showing `disabled`/`disabled` and `poe.after` showing `enabled` and a state other than `disabled`;
- a fresh `show configuration` equals the state before;
- the check account sees `Configured Admin State: enabled` and a state other than `disabled`.

With that proof recover records the step `cycle_proven` and the record field `poe.recovered`, removes the safeguard, verifies the configuration again and saves it. The result is `confirmed` with the reason `cycle confirmed before the interruption; safeguard removed by recover`, or `powered device not delivering after the cycle` when the port was `delivering` before and is not now. Without the proof recover records `cycle_unproven` with the cause and lets the safeguard fire, which runs `enable inline-power ports N`. The result is then settled like any expiry, normally `reverted` with the reason `interrupted; PoE cycle not proven`. It never reports a cycle that was not proven.

`reset inline-power ports N` is not used: on a port without PoE it is silent (empty output, exit status 0) and its off time varied from 3 s to 40 s (measured on 2026-11-14, task 171), so neither a refusal nor the cycle itself would be observable.

| Code | Refused PoE cycle |
|---|---|
| `poe_not_capable` | `Port N is not inline-power capable` |
| `poe_unsupported` | the switch gives no inline-power table (a platform without PoE) |
| `poe_disabled` | inline power of the port is configured disabled or its state is `disabled` |
| `poe_state_unreadable` | the inline-power answer is not recognised or names another port |
| `safeguard_margin_insufficient` | `safeguard_seconds` leaves less than the cycle budget (175 s) plus `confirm_margin_seconds`; checked from the configuration before any read and again on the switch clock after the safeguard is installed |
| `port_protected` | listed in `protected["ports"]` or `protected["inline-power"]` |

**Not measured.** The state `delivering` with a real powered device and the time until such a device is powered again (no powered device was connected; all ports were `searching`). The operation does not depend on it: the configuration and `Configured Admin State` are verified as measured, and the observed power state is reported. The read-only check account read `show inline-power info detail` in the Admin runs on the two switches (2026-11-14, task 184). The safeguard margin check and the recover classification of 1.0.10 (task 305) change only decisions in Admin, not the commands or waits of the cycle on the switch: they add one read, `show switch`, for the clock, and recover decides without waiting for the safeguard timer. They are verified by automated tests against the simulated switch, with `show inline-power info detail` outputs measured in task 171. They were not run on a switch.

## Arista EOS interface description, admin state and access VLAN

Platform `eos`, measured only on cEOSLab 4.36.1F (GNS3 lab, 2026-11-15/16, tasks 301 and 304); the profiles list `4.36.1F` as an exact version, so every other EOS release is refused before any write. Tables (`update` only, CLI and MCP `admin_preview`/`admin_apply`/`admin_undo_preview`, operator `admin undo`):

| Table | Attribute | Device lines | Read-back of the check account |
|---|---|---|---|
| `interface` | `description` (text, at most 64 characters) | `description TEXT` / `no description` | `show interfaces N description` |
| `interface` | `admin-state` (`enabled`/`disabled`) | `no shutdown` / `shutdown` | `show interfaces N status` (`disabled`) |
| `vlan-membership` | `access-vlan` (1–4094, default 1) | `switchport access vlan N` / `no switchport access vlan` | `show interfaces N switchport` (`Access Mode VLAN`) |

The key is the full interface name, for example `Ethernet10`. Example: `{"table": "interface", "op": "update", "key": "Ethernet10", "changes": {"description": "netops-test"}}`.

**Accounts and roles.** The write account must log in with privilege 15 (`aaa authorization exec default local` and `username <write> privilege 15 role network-admin`); Admin reads the running configuration with one SSH exec command and never sends `enable` or an enable secret. A write account that logs in with another privilege is refused (`write_account_privilege`). The check account (for example role `network-operator`, privilege 1) only reads `show interfaces N status|description|switchport`. Without command authorization any account reaches privilege 15 with `enable` when no enable secret is set, so the check account is then not really read-only; the measured lab therefore also has `aaa authorization commands all default local`, under which `network-operator` is refused `configure terminal` and `configure session` (`% Authorization denied`). The device entry needs `accounts` (the `username` lines of the running configuration); `audit_policy` is not supported, because the Auditor holds no EOS rules (the audit gate reports 0 rules).

**Safeguard and return.** Before the change Admin commits an empty configuration session `netops-<12 hex>` with `commit timer` of `safeguard_seconds`; its checkpoint is the configuration before the change. The change then runs line by line through `configure terminal` in an interactive session (an SSH exec batch continues after an error, so it is never used for configuration). Confirmation is `configure session netops-<id> commit` followed by `no configure session netops-<id>`; `write memory` runs only after it, because during the pending timer it would save the unconfirmed state. When the timer expires, EOS returns the **whole** running configuration to the checkpoint of the session: a change of someone else made in the timer window is returned too. The session then disappears; while Admin waits for the timer of a running change it accepts the return only with the log lines `CONFIG_SESSION_COMMIT_TIMER_TIMEDOUT` and `CONFIG_SESSION_COMMIT_REVERTED` of that session (`show logging last 60 minutes`) and a snapshot equal to the state before. `admin recover` of an interrupted change is weaker: when the session is already gone and the running configuration equals the state before the change, it saves the configuration and records `reverted` without reading the log (for example after more than 60 minutes, when the log lines are out of the read window); such a `reverted` is proven by the configuration matching the state before, not by log events of the timer. While the timer is pending EOS refuses every other commit timer and the commit of other sessions. Behaviour of a pending timer across a reload was not measured.

Admin refuses, before any write:

| Code | Refused |
|---|---|
| `port_management_interface` | a `Management` interface |
| `port_unsupported_interface` | an interface that is not `EthernetN` (loopback, VLAN interface, port-channel) |
| `vlan_missing` | an access VLAN that is not in the running configuration or not in `show vlan id N` (EOS would create it silently) |
| `port_uplink` | for a change of the admin state (down **or** up) or of the access VLAN: a trunk (`switchport mode trunk`, `switchport trunk ...`) or a port that is not `static access` |
| `port_lag_member` | the same, a `channel-group` member |
| `port_routed` | the same, a routed port (`no switchport`) |
| `port_lldp_neighbor` | an admin state change (down or up) or an access VLAN change of a port with an LLDP neighbor |
| `port_learned_mac` | the same, a port with learned MAC addresses |
| `foreign_config_session` | an open (`pending`) configuration session or a pending commit timer of someone else |

An interface that is not in the running configuration is refused too (EOS would create it). Admin up gets the same checks as admin down, because enabling a disabled uplink or port-channel member can bring back a loop. A description change of a trunk port is allowed; the description alone gets none of these port checks. Unsaved changes of someone else (`show running-config diffs` not empty) and a leftover `netops-` session are refused. Enrollment (`admin enroll --device D --probe Ethernet10`) sets the description of the probe interface to `netops-enroll-<hex>` and lets the commit timer return it.

## Cisco IOS and IOS XE interface description, admin state and access VLAN

Platforms `ios` (IOS 15.x) and `iosxe` (IOS XE 17.x), one adapter for both. Measured only in the GNS3 lab (2026-11-16, tasks 310 and 315) on four images; the profiles list these firmware strings as exact versions, so every other release is refused before any write:

| Platform | Image (lab node) | `firmware` | Tables |
|---|---|---|---|
| `ios` | IOSv `VIOS-ADVENTERPRISEK9-M` (router) | `15.9(3)M12` | `interface` |
| `ios` | IOSvL2 `vios_l2-ADVENTERPRISEK9-M`, experimental image (switch) | `15.2(20200924:215240)` | `interface`, `vlan-membership` |
| `iosxe` | IOL XE `X86_64BI_LINUX-ADVENTERPRISEK9-M` (router) | `17.18.2` | `interface` |
| `iosxe` | IOL-L2 XE `X86_64BI_LINUX_L2-ADVENTERPRISEK9-M` (switch) | `17.18.2` | `interface`, `vlan-membership` |

Tables (`update` only, CLI and MCP `admin_preview`/`admin_apply`/`admin_undo_preview`, operator `admin undo`):

| Table | Attribute | Device lines | Read-back of the check account |
|---|---|---|---|
| `interface` | `description` (text, at most 64 characters) | `description TEXT` / `no description` | `show interfaces description` (column Description) |
| `interface` | `admin-state` (`enabled`/`disabled`) | `no shutdown` / `shutdown` | `show interfaces description` (Status `admin down`) |
| `vlan-membership` | `access-vlan` (1–4094 without 1002–1005, default 1) | `switchport access vlan N` (the return to VLAN 1 is `switchport access vlan 1`) | `show interfaces N switchport` (`Access Mode VLAN`) |

The key is the full interface name, for example `GigabitEthernet0/2` or `Ethernet0/1`. Example: `{"table": "interface", "op": "update", "key": "GigabitEthernet0/2", "changes": {"description": "netops-test"}}`. The access VLAN is set only on the switch images (the router images have no `switchport`; on the IOS XE router it is refused with `port_routed`, on IOSv the profile has no measured version for it).

**Device entry.** `platform` `ios` or `iosxe`, `firmware` (required: the running configuration names only the release train, `version 15.9` or `version 17.18`; Admin compares the stated firmware with the first line of the live `show version` before any write and refuses another release, or IOS XE configured as `ios` and the reverse), `accounts` (the `username` lines of the running configuration) and the `legacy_ssh` profile the device needs (measured: `rsa-sha1-dh14` for IOSv and IOSvL2, `rsa-sha1` for IOL XE and IOL-L2 XE, whose host keys are RSA). `audit_policy` is not supported, because the Auditor holds no IOS rules (the audit gate reports 0 rules).

**Prerequisite on the device.** The configuration archive: `archive` / ` path flash:netops-archive` (IOL XE: ` path unix:netops-archive`) / ` maximum 14`. Without it `show archive` names no archive maximum and Admin refuses with `archive_not_configured`. The archive files `netops-archive-<timestamp>-N` rotate at the maximum; Admin never deletes them.

**Accounts and roles.** The write account must log in with privilege 15 (`username <write> privilege 15 secret ...`); Admin reads the running configuration with one SSH exec command and never sends `enable` or an enable secret (`write_account_privilege` otherwise). An SSH exec command of IOS has exit status 0 even when IOS refuses it (`Line has invalid autocommand "..."`) and takes one line only, so Admin treats that answer as a refusal and never uses exec for configuration. The check account (privilege 1) reads `show interfaces description` and `show interfaces N switchport`; on IOS privilege 1 it cannot read `show running-config`, `show archive` or `show logging` and is refused `configure terminal`, `configure confirm` and `write memory` (measured). The measured lab grants privilege 1 the command `show` (`privilege exec level 1 show`). `admin doctor` refuses a check account with privilege 15.

**Safeguard and return.** Before the change Admin sends `configure terminal revert timer N` and `end` in an interactive session; N is `safeguard_seconds` rounded up to whole minutes, at least 2 (2–15; the device has no finer granularity, see the minimum below). IOS saves the running configuration to a new archive file at once and starts an absolute timer when the configuration mode ends. The timer is Admin's own only with proof from its own session: the answer to its own request names the new archive (`Rollback Confirmed Change: Backing up current running config to <archive>`, not `%Rollback Confirmed Change is already activated on a config`), that archive is the new most recent one of `show archive`, and `show archive config rollback timer` then shows `Timer type: absolute timer`, `Timer value: N min` and `User:` the write account. Admin records the archive name, `Time configured` and the minutes as the identity of its safeguard (IOS gives the timer no name; `safeguard.name` `netops-<12 hex>` only names the operation in the journal and the audit log, and `safeguard.fire_at` reads `device revert timer`). A pending timer is its own only when the installation was proven this way and the timer still has the recorded time configured, minutes and user; the same account and a similar time are never enough.

**Refused or unverified installation.** When the device refuses the own request (`already activated`: another session, also of the same account, started a timer after the prechecks), the operation ends `rejected` (`rollback_timer_pending`, reason `safeguard refused by the device`) and nothing was changed. When the own session reported the archive but the timer could not be verified, the operation ends `unknown` (`safeguard not verified`) and the device is blocked. In neither case does Admin send `configure confirm`, `configure revert now` or `write memory`: a timer that is not proven its own is left to its owner or to its expiry, which returns only the empty change of the own request. `admin recover` does not confirm it either.

**Protection during the whole change.** Admin never reads the device clock (the measured IOSv clock was almost three hours behind UTC and drifted by 1.7 %; IOL XE shows CET while its log is in UTC). The time left on the own timer is counted on the monotonic clock of Admin from the moment before the timer was requested, shortened by 2 % for the drift of the device clock, so Admin's count never ends after the device's. Right before the change is written Admin reads `show archive config rollback timer` again: the own timer must still be pending and at least 40 s plus `confirm_margin_seconds` must be left (20 s for the write session and 20 s for the readback, see below). Otherwise nothing is written (step `change_not_written`) and the own timer, if still pending, is returned with `configure revert now` (else Admin waits until no own timer is pending); with the state before proven the result is `reverted` with reason `no time left to write`. During the write session every configuration line is sent only while at least 10 s are left; a line that is not sent ends the write as `change failed`. Before `configure confirm` at least `confirm_margin_seconds` must be left on the same count (`no time left to confirm` otherwise).

**Minimum timer of 2 minutes.** Measured maxima on the four lab nodes (`ref/mereni-c4c5/ops.log`): `configure terminal revert timer` 5.8 s, interactive login 1.6 s (2.9 s with the IOSv banner), an SSH exec read 1.1 s, `show running-config` 6.1 s, a configuration line 1.0 s, `configure confirm` 0.2 s, `configure revert now` 11.0 s. Until the change is written Admin spends about 13 s (installation and three reads). A write session of at most five lines takes about 8 s (budget 20 s); the snapshot, the check account and the final snapshot take about 13 s (budget 20 s); then `confirm_margin_seconds` (15–45 s) must be left. One minute (58.8 s after the drift allowance) is shorter than even 13 + 20 + 20 + 15 = 68 s; two minutes (117.6 s) leave room for the default margin of 45 s (98 s). A device that answers far slower than measured makes Admin stop before the write or before a line, never write without the timer.

**Confirmation and return.** The change runs line by line through `configure terminal` (IOS accepts it while the timer is pending). Confirmation is `configure confirm`, sent only for the own timer; `write memory` runs only when no revert timer is pending, because during a pending timer it saves the unconfirmed state without a warning. When the write or the readback of a normal operation fails (a refused or unsent line, a postcheck or check-account failure or mismatch, too little time to confirm, a final check that differs, an unproven confirmation), Admin returns at once with `configure revert now` from its own session, only while its own timer is pending; the answer must name the own archive (`Rollback Confirmed Change: rolling to:<archive>`) and the timer must be gone afterwards (steps `revert_now_start`, `revert_now_done`). A fresh snapshot equal to the state before then gives `reverted` and `write memory`; another state gives `revert-failed`. Only when `configure revert now` cannot be sent or proven (step `revert_now_unverified`) Admin waits for the expiry. The enrollment self-test is left unconfirmed on purpose and returned by the expiry. `configure revert now` and the expiry replace the **whole** running configuration with the archive: a change of someone else made in the timer window is returned too. IOS XE returns at once, IOS within about 7 seconds after the expiry, during which `show archive config rollback timer` still shows the timer.

**Waiting and recover.** Waiting for the expiry and `admin recover` of an interrupted operation decide by the state of the timer, never by the clock of the device: Admin reads `show archive config rollback timer` every 10 s (a failed read counts as still pending) until the own timer is no longer pending (`%No Rollback Confirmed Change pending` or a timer without the recorded identity), limited to 980 s on the monotonic clock of Admin (the longest timer of 15 minutes plus grace and slack; then `unknown`). `admin recover` leaves an interrupted operation to the expiry and does not send `configure revert now`. Admin accepts the return only when the timer is no longer pending and a fresh snapshot equals the state before; the log lines `%ARCHIVE_DIFF-5-ROLLBK_CNFMD_CHG_ROLLBACK_START: Start rolling to: <archive>` and `..._CONFIRM` are read as additional evidence only (state `fired`/`disarmed`), because IOL keeps a log buffer of 4096 bytes that a few SSH logins overwrite. Behaviour of a pending timer across a reload was not measured.

**The timer belongs to the device.** Any privilege-15 session can confirm, extend (`configure revert timer N`) or start the return (`configure revert now`) of a pending timer, and a second `configure terminal revert timer` is refused with `%Rollback Confirmed Change is already activated on a config`. Admin therefore refuses any pending timer before the write (`rollback_timer_pending`; an own timer of an earlier operation is reported as a leftover safeguard) and sends `configure confirm` and `configure revert now` only for the timer whose installation its own session proved (see above), and only after `show archive config rollback timer` in the same interactive session, right before the command, still shows that timer (else the command is not sent). The check and the command are still not atomic: the timer is global and carries no owner, so another privilege-15 session that confirms the own timer, or starts a new one right after it expired, within that fraction of a second is not detected; nobody else should use `configure` on the device while an operation of Admin runs.

Admin refuses, before any write:

| Code | Refused |
|---|---|
| `archive_not_configured` | the configuration archive is not configured (`show archive`) |
| `rollback_timer_pending` | a pending revert timer of anyone (`show archive config rollback timer` is not `%No Rollback Confirmed Change pending`) |
| `port_management_interface` | the interface that carries the local address of an SSH session of the device (`show tcp brief` with `show ip interface brief`), or an interface in a VRF whose name contains `mgmt` or `management` |
| `port_management_vlan` | a switch port whose access VLAN is the VLAN of that management interface (an SVI `VlanN`), and an access VLAN change into it |
| `port_unsupported_interface` | an interface that is not a physical Ethernet port (subinterface, `Vlan`, `Loopback`, `Port-channel`, `Serial`) |
| `vlan_missing` | an access VLAN that `show vlan id N` does not know: IOS would create it, and a VLAN of the normal range lives in `vlan.dat`, which the rollback does not remove (measured with VLAN 333) |
| `vlan_reserved` | the access VLANs 1002–1005 |
| `port_uplink` | for a change of the admin state (down **or** up) or of the access VLAN: a trunk (`switchport mode trunk`, `switchport trunk ...`), a port that negotiates trunking, or a switch port whose `Administrative Mode` is not `static access` |
| `port_lag_member` | the same, a `channel-group` member |
| `port_routed` | the same, a routed switch port (`no switchport`); and an access VLAN on a router image |
| `port_ip_address` | the same, an interface that carries an IPv4 address itself or on a subinterface (on a router an addressed interface is in use) |
| `port_lldp_neighbor` | the same, a port with a neighbor in `show lldp neighbors` or `show cdp neighbors` |
| `port_learned_mac` | the same on a switch, a port with learned MAC addresses (`show mac address-table interface N`) |
| `port_usage_unreadable` | an answer of these reads that is not recognised, or a management interface that cannot be identified |

An interface that is not in the running configuration is refused too (IOS answers `% Invalid input`). A description change of a trunk port is allowed; the description alone gets only the management checks. Unsaved changes of someone else (`show archive config differences nvram:startup-config system:running-config` names another difference than the permanent self-signed certificate `crypto pki certificate chain TP-self-signed-...` of IOS XE) are refused, because Admin saves the configuration after its change. Enrollment (`admin enroll --device D --probe GigabitEthernet0/2`) sets the description of the probe interface to `netops-enroll-<hex>` and lets the revert timer return it.

**End-to-end run.** On 2026-11-16 (02:08–03:12 UTC) a locally built image of the development source `3dd813e` passed the operator command line scenarios on all four lab nodes (IOSv Gi0/2, IOSvL2 Gi1/0, IOL XE Et0/2, IOL-L2 XE Et0/1; `safeguard_seconds` 120): `doctor`, enrollment self-test (`reverted` by the revert timer), description preview, apply with `--expect-plan-sha256`, undo preview and undo, `no shutdown` and `shutdown`, SIGKILL of the Admin process right after the change followed by `admin recover` (`reverted` after the timer expired), on both switches access VLAN 10 and its undo (`switchport access vlan 1`), all `confirmed` and read back by the separate privilege-1 check account; refusals without a write: VLAN 3999 (`vlan_missing`), VLAN 99 and the management port (`port_management_vlan`), the management interface of the routers (`port_management_interface`). The running configuration, the test ports, `show vlan brief`, startup = running and no pending timer were the same after the run as before. On IOL-L2 XE the management address was unreachable twice during the run for several minutes (once right after an admin up, once during reads only); Admin then recorded `unknown` (`check identity unavailable`, no confirmation) and blocked the device, the revert timer returned the port, and after the investigation and `admin unblock` the same admin up and down passed. The MCP tools were not called in this run; they use the same preview and apply path. Not measured: a pending timer across a reload, `configure terminal revert timer idle`, and other images or releases than the four above.

## Cisco NX-OS interface description, admin state and access VLAN

Platform `nxos`, measured only on a Nexus 9000v (N9K-C9300v, virtual) with NX-OS 9.3(12) in the GNS3 lab (2026-11-16, tasks 314, 317 and 318); the profiles list `9.3(12)` as an exact version, so every other NX-OS release is refused before any write. A physical Nexus 9000 is not verified. Tables (`update` only, CLI and MCP `admin_preview`/`admin_apply`/`admin_undo_preview`, operator `admin undo`):

| Table | Attribute | Device lines | Read-back of the check account |
|---|---|---|---|
| `interface` | `description` (text, at most 64 characters) | `description TEXT` / `no description` | `show interface description` (the row of the port) |
| `interface` | `admin-state` (`enabled`/`disabled`) | `no shutdown` / `shutdown` | `show interface N status` (`disabled`) |
| `vlan-membership` | `access-vlan` (1–4094, default 1) | `switchport access vlan N` / `no switchport access vlan` | `show interface N switchport` (`Access Mode VLAN`) |

The key is the full interface name, for example `Ethernet1/48`. Example: `{"table": "interface", "op": "update", "key": "Ethernet1/48", "changes": {"description": "netops-test"}}`.

**Accounts and roles.** The write account (measured with role `network-admin`) reads the running configuration with one SSH exec command (`show running-config`; NX-OS prints no closing `end`, so a snapshot without its header or without `interface mgmt0`, `line vty` and `boot nxos` is refused as cut off) and runs the change, the safeguard and the save in interactive sessions without `enable`. The check account (measured with role `network-operator`) is really read-only on NX-OS: it may not read `show running-config` or `show scheduler`, so Admin reads its state only from `show interface N status`, `show interface description` and `show interface N switchport`. The device entry needs `accounts` (the `username` lines of the running configuration) and the SSH profile `legacy_ssh: "rsa-sha1"` when the switch offers only an RSA host key with SHA-1 signatures (the lab node does). `audit_policy` is not supported, because the Auditor holds no NX-OS rules (the audit gate reports 0 rules). A least-privilege custom role for the write account was not measured.

**Precondition `feature scheduler`.** NX-OS 9.3(12) has neither a commit timer nor an EEM timer event; the only timed return that runs without the Admin session is a one-time job of `feature scheduler`. The administrator of the switch enables it once (`configure terminal`, `feature scheduler`, `end`, `copy running-config startup-config`) and leaves it enabled. Admin never enables or disables it: every `no feature scheduler` creates a system checkpoint and evicts the oldest of the five system checkpoints (measured). Without it every change is refused with `scheduler_feature_disabled`, and `admin doctor` reports it in `device prechecks`.

**Safeguard and return.** Before the change Admin installs, in one interactive session: `checkpoint netops-<12 hex>`, the scheduler job `netops-<id>` with `rollback running-config checkpoint netops-<id> atomic`, the scheduler schedule `netops-<id>` with `job name netops-<id>` and `time start +M`, then `no checkpoint netops-<id>` and `checkpoint netops-<id>` again (the checkpoint now holds the job and the schedule, so the rollback never has to delete the running job; a job created after its checkpoint makes the rollback fail and blocks the scheduler until `no feature scheduler`, measured), and `copy running-config bootflash:netops-<id>-pred.cfg`. Admin verifies the job, the schedule, the checkpoint (`show diff rollback-patch running-config checkpoint netops-<id>` must be empty), the file and the lead of the schedule before it writes the change. The schedule has a granularity of one minute: `time start +M` starts at the next whole minute plus M−1 minutes, so the real delay is between M−1 and M minutes; Admin takes M = ceil(`safeguard_seconds` / 60) + 1. The change runs line by line through `configure terminal` (`configure session` offers neither `description`, `shutdown` nor `switchport` under an interface on 9.3(12)). Confirmation deletes the schedule, then the job, then the checkpoint and the file; `copy running-config startup-config` runs only after it, and `show running-config diff` must then be empty. The operation records `safeguard.fire_at` as `device scheduler job`; `safeguard.device_time` is the time of the job as the switch shows it (information only).

**Own objects only.** The name `netops-<id>` must be free of every checkpoint, job, schedule and file right before the installation; otherwise nothing is installed (a foreign object of that name is left alone, the operation ends `unknown` with `safeguard not verified` and the device is blocked). An object is Admin's own only when the line that creates it was answered without an error in Admin's own session: Admin notes that line by line in `safeguard.own` (and the phase of the installation in `safeguard.phase`) and the journal saves each note at once. Every removal (confirmation, cleanup after the run, an unverified or interrupted installation, `admin recover`) touches only own objects; the name derived from the change ID is never enough. Limit: NX-OS enters an existing scheduler job of the same name without a message (not measured otherwise), so a job created by someone else in the seconds between the name check and the own `scheduler job name` line cannot be told apart.

**Protection during the whole change.** Admin never reads the device clock. The job runs at least M−1 minutes after the switch took `time start +M`; Admin counts that on its monotonic clock from the moment before the installation started, 2 % shorter for the drift of the device clock, and never longer than the lead the switch itself shows (the time of the schedule less the creation time of the checkpoint, both in `show` output of the switch; a lead that does not fit `time start +M` is `safeguard not verified`). Right before the change is written the own schedule must still be pending (`show scheduler schedule name netops-<id>`) and at least 60 s plus `confirm_margin_seconds` must be left (20 s for the write session, 40 s for the readback); otherwise nothing is written (step `change_not_written`, reason `no time left to write`) and the safeguard is removed. Every configuration line is sent only while at least 15 s are left (a line that is not sent ends the write as `change failed`), and `confirm_margin_seconds` must be left before the confirmation. With the default margin of 45 s this needs `safeguard_seconds` of at least 180 (M = 4, 176 s of protection; the installation takes about 10–20 s of it).

**Return.** When the job runs, NX-OS rolls the **whole** running configuration back to the checkpoint about 3 s after the minute (measured 6–9 s): a change of someone else made in the window is returned too. A change that Admin itself finds unverified (failed write, failed read-back of the check account, prediction mismatch, too little time to confirm) is returned at once, without waiting for the minute of the job: `configure replace bootflash:netops-<id>-pred.cfg` (measured `Success`, the access VLAN included; steps `revert_now_start`, `revert_now_done`), sent only while at least 60 s of the protection are left and never while a rollback runs. Only when the snapshot then shows the object in its state before is the safeguard removed; otherwise (and with less than 60 s left, step `revert_now_skipped`) Admin waits for the job. Waiting and `admin recover` decide by the state of the scheduler, never by the device clock: Admin reads `show scheduler schedule name netops-<id>` every 10 s until the job has run to its end (the schedule shows an execution, `show rollback log verify` shows no running rollback, and `show scheduler logfile` or `show rollback log exec` names the job) or the schedule is gone, limited to 980 s on its monotonic clock (then `unknown`). It accepts the return only with a snapshot equal to the state before; when the object is still changed after the run (a line that arrived late, or a change of someone else after the return; step `expiry_not_returned`), the same `configure replace` of the own file is tried before the result is given up. Then it removes the job, the schedule (NX-OS refuses that for a while after the run; repeated every 20 s for up to 5 minutes while the switch answers `schedule in progress`), the checkpoint and the file. The enrollment self-test and `admin recover` of an interrupted change always wait for the job. `configure replace ... commit-timeout` is not used: its automatic return left a changed access VLAN in place and always reported `Failed` (measured). Behaviour of a pending job across a reload of the switch was not measured.

**Interrupted or unverified installation.** As long as the change was not sent (no step `change_start`), the safeguard is removed at once, by the operation itself (installation not verified) or by `admin recover` (step `installation_interrupted` with the phase): a pending own schedule first, so its job can no longer start, then the own job, checkpoint and file; the result is `reverted` with reason `safeguard not verified` or `interrupted`. This also covers the dangerous phase between `time start +M` and the second `checkpoint netops-<id>`, in which the job is armed while its checkpoint does not hold it yet: run in time, recover deletes the schedule and the job before the job starts. What Admin cannot do, and reports as `unknown` (reason `interrupted safeguard installation; manual cleanup needed`, the device blocked, the objects left in the step `safeguard_removal_unverified` and the manual procedure in `safeguard.manual_cleanup` of the operation, shown by `admin status`): remove an object whose creating line was sent but whose answer never reached Admin (it is not proven own), and recover a job of that phase that has already run, because it stays `schedule in progress` and only `no feature scheduler` removes it. Admin never sends `no feature scheduler`; that is a decision of the switch administrator (it creates a system checkpoint and evicts the oldest one), after which `feature scheduler` must be enabled again. The manual procedure, after checking that the objects are not someone else's: `configure terminal` / `no scheduler schedule name netops-<id>` / `no scheduler job name netops-<id>` / `end` / `no checkpoint netops-<id>` / `delete bootflash:netops-<id>-pred.cfg no-prompt` / `copy running-config startup-config`, then `admin unblock`.

Admin refuses, before any write:

| Code | Refused |
|---|---|
| `port_management_interface` | `mgmt0` (NX-OS would accept `description` and `shutdown` there) |
| `port_unsupported_interface` | an interface that is not `EthernetX/Y` (loopback, VLAN interface, port-channel) |
| `vlan_missing` | an access VLAN that is not in the running configuration or not in `show vlan id N` (NX-OS would accept it silently and leave the port `inactive`) |
| `vlan_reserved` | an access VLAN 3968–4094 (reserved on NX-OS) |
| `port_uplink` | for a change of the admin state (down **or** up) or of the access VLAN: a trunk (`switchport mode trunk`, `switchport trunk ...` or a port listed in `show interface trunk`) or a port whose operational mode is not `access` |
| `port_lag_member` | the same, a `channel-group` member |
| `port_routed` | the same, a routed port (`no switchport`, or `Switchport: Disabled`) |
| `port_learned_mac` | an admin state change (down or up) or an access VLAN change of a port with learned MAC addresses (`show mac address-table interface N`) |
| `port_lldp_neighbor` | the same, a port with an LLDP neighbor (only an addition: the measured uplink had no LLDP neighbor, so the trunk check carries the uplink protection) |
| `scheduler_feature_disabled` | `feature scheduler` is not enabled |
| `foreign_config_session` | an open configuration session (`show configuration session summary`) |
| `rollback_in_progress` | a rollback or configure replace that has started and not ended (`show rollback log verify`) |

An interface that is not in the running configuration is refused too. Unsaved changes (`show running-config diff` not empty; the return would roll them back) and any leftover `netops-` checkpoint, scheduler job or schedule or `bootflash:netops-*` file are refused. Admin up gets the same checks as admin down; a description change of a trunk port is allowed. Enrollment (`admin enroll --device D --probe Ethernet1/48`) sets the description of the probe interface to `netops-enroll-<hex>` and lets the scheduler job return it, so it takes up to M minutes plus the cleanup after the run (up to about 3 more minutes).

## Juniper Junos interface description, admin state and access VLAN

Platform `junos`, measured only on vJunos-switch 26.2R1.7 (ELS, model ex9214; GNS3 lab, 2026-11-16, tasks 308 and 319); the profiles list `26.2R1.7` as an exact version, so every other Junos release is refused before any write. Physical EX switches, non-ELS Junos (`port-mode`) and routers (MX, SRX) are not measured and not supported. Tables (`update` only, CLI and MCP `admin_preview`/`admin_apply`/`admin_undo_preview`, operator `admin undo`):

| Table | Attribute | Device lines | Read-back of the check account |
|---|---|---|---|
| `interface` | `description` (text, at most 64 characters, letters, digits, space and `._:/()+-`) | `set interfaces IF description "TEXT"` / `delete interfaces IF description` | `show interfaces descriptions` |
| `interface` | `admin-state` (`enabled`/`disabled`) | `delete interfaces IF disable` / `set interfaces IF disable` | `show interfaces IF terse` (Admin `down`) |
| `vlan-membership` | `access-vlan` (a VLAN **name**, default `default`) | `delete interfaces IF unit 0 family ethernet-switching vlan members` and `set ... vlan members NAME` | `show ethernet-switching interface IF` (the one `untagged` VLAN) |

The key is the interface name, for example `ge-0/0/2`. Example: `{"table": "vlan-membership", "op": "update", "key": "ge-0/0/2", "changes": {"access-vlan": "D10"}}`. Admin always quotes the description (a text with a space is a syntax error without quotes, measured). `set ... vlan members` adds a member instead of replacing it (measured), so the old member is deleted first. An access VLAN change needs an access port (`unit 0 family ethernet-switching interface-mode access`); a port without it is refused with `port_not_access`, Admin does not create the switching family. A VLAN number in place of a name is not accepted (Junos accepts a numeric member that does not exist at commit time, measured).

**Device entry.** `safeguard_seconds` must be `600` and `confirm_margin_seconds` at least `240` (see the timing below); the entry needs `accounts` (the `set system login user` names of the configuration). `audit_policy` is not supported, because the Auditor holds no Junos rules (the audit gate reports 0 rules).

**Accounts and roles.** The write account needs the login-class permissions `configure`, `view` and `view-configuration` (`show cli authorization`; otherwise `write_account_privilege`); it reads the configuration with one SSH exec command (`show configuration | display set`; for a class with the permission `secret` the answer holds the password hashes, and Admin keeps only hashes of the snapshot and the parsed object, never its text) and changes it only in an interactive session (an SSH exec batch answers with status 0 even for an error and continues after it, measured). The measured lab uses the existing class `super-user`. A narrower class was **not created and not verified**; the measurement proposes, as a recommendation for the administrator:

```
set system login class netops-admin permissions [ configure interface interface-control view view-configuration ]
set system login class netops-admin allow-configuration-regexps "interfaces (ge|xe|et|mge)-[0-9/]+ (description .*|disable|unit 0 family ethernet-switching vlan members .*)"
set system login user <write account> class netops-admin
```

Not verified: whether such a regular expression also covers the `delete` lines and the empty `commit confirmed` of the safeguard. The check account of the built-in class `read-only` reads only operational state (`show interfaces IF terse`, `show interfaces descriptions`, `show ethernet-switching interface IF`); it cannot read the configuration or the log and has no configuration mode (measured).

**Safeguard and return.** Junos has no session timer of its own besides `commit confirmed`, and every commit (also `commit check`) confirms a pending one (measured; `commit check` leaves no trace in the commit history or the log). Admin therefore works only in `configure exclusive` (`configure private` refuses `commit confirmed`, measured) and in this order:

Every interactive session starts with `set cli screen-width 1024`, a setting of that CLI session only (not of the configuration): the terminal of Admin has no width, Junos then uses 80 columns and redraws the prompt in the middle of the echo of a longer line, which a prompt reader takes for the end of the line (measured in task 319; the first enrollment attempt ended `reverted` with `change failed` because of it, before any change was committed).

1. Before any change it enters the shared configuration mode once and leaves it again: another user in configuration mode (`Users currently editing the configuration`) or an uncommitted change of someone else (`The configuration has been changed but not committed`) is refused with `foreign_config_session`; so is a pending `commit confirmed` of someone else (a `rollback pending` row whose comment does not start with `netops-` in `show system commit`).
2. Safeguard: `configure exclusive`, an empty candidate (`show | compare` must be empty), `commit confirmed 10 comment "netops-<12 hex>"`; Admin verifies its `rollback pending` row. The answer of that `show | compare` carries the banner `# commit confirmed will be rolled back in N minutes` whenever any commit confirmed is pending (measured): when it is there, a timer of someone else appeared after the prechecks and the safeguard commit is not sent (it would confirm that timer); the operation ends `rejected` (`foreign_config_session`, reason `safeguard refused by the device`) and nothing was changed.
3. Change: `configure exclusive`, an empty candidate, the `set`/`delete` lines, `show | compare` and `commit confirmed 10 comment "netops-change"`. This commit restarts the timer from itself (measured: the expiry then returns the change too); Admin reads the new commit row, which must be the write account's pending commit right above its own safeguard row, and records it as the new head of its timer. A commit that does not answer `commit complete` is a failed change (a refused VLAN name answers `error: configuration check-out failed`).
4. Readback of the write account (snapshot) and of the check account, then confirmation `commit comment "netops-<12 hex>-ok"`, sent only while the empty candidate still shows the banner of the pending timer (a plain commit during the automatic rollback makes it fail, measured); the `rollback pending` row must be gone and the newest row must be the own `-ok`. A Junos commit is the saved configuration, so nothing else is saved.


**Own timer only.** Junos gives a pending `commit confirmed` no owner, and every commit of any session confirms it, also of the same account. The timer is Admin's own only with proof from its own session: its install session answered `commit complete`, and right after it the newest row (record 0) of `show system commit` is its own comment `netops-<12 hex>` of the write account with `rollback pending`. Admin records that row (time, user, comment) as the safeguard and the later own `commit confirmed` of the change as the head. The confirmation, the immediate return and `admin recover` send a commit only while the newest row is exactly the recorded head with `rollback pending` above the recorded safeguard row; the same account, the prefix `netops-` or the comment alone are never enough, and a timer that is not proven Admin's own is left to its owner or to its expiry. An installation that is not proven (for example the commit history cannot be read right after the safeguard commit) ends `unknown` (`safeguard not verified`, the device is blocked); `admin recover` then sends nothing while a rollback is pending and clears the record once none is. Not covered: another privileged session that commits within the seconds between Admin's last read and its commit line (Junos has no identity of the owner of a timer); Admin then sees a foreign row in place of its head and does not confirm.

**Protection during the whole change.** Admin never reads the device clock for the safeguard. The timer counts whole minutes from its commit row (written at the end of the commit) and expired 0-60 s after them, so Admin counts 600 s less 2 % for the drift of the device clock on its monotonic clock from the moment before the safeguard was requested. Right before the change session Admin reads `show system commit` again: its own timer must still be pending, and at least 240 s (the change session with its commit; 126-235 s in the E2E of task 319, commits 15-150 s) and at least 90 s (the readback) plus `confirm_margin_seconds` plus 15 s must be left (the change commit restarts the timer with the same uncertainty of its start, so the time left after the commit is about the time left before it). Otherwise nothing is written (step `change_not_written`, reason `no time left to write`). Every line of the change session up to its commit is sent only with at least 180 s left (a line that is not sent is a failed change). After the change commit the end of the timer moves by the device time between the safeguard row and the change row (both on the device clock, shortened for the drift), never past the answer of the session; before the confirmation `confirm_margin_seconds` must be left on that count (`no time left to confirm` otherwise).

**Immediate return.** When the write or the readback of a normal operation fails (a refused or unsent line, a postcheck or check-account failure or mismatch, too little time to write or to confirm, an unproven confirmation), Admin returns at once while its own timer is pending with at least 240 s left: when no own change commit exists yet, the configuration is that of the empty safeguard and the return is its confirmation; otherwise the inverse `set`/`delete` lines of the plan are committed with the plain `commit comment "netops-<12 hex>-revert"` (steps `revert_now_start`, `revert_now_done`), which ends the own timer and keeps the inverse; the `rollback pending` row must be gone and the newest row must be that own `-revert` row right above the head. The inverse is not committed with `commit confirmed`: the expiry of a timer returns the configuration before the newest `commit confirmed`, so an inverse under a timer that is then not confirmed (the process interrupted) brings the change back (measured live in task 378). A fresh snapshot then decides: equal to the state before is `reverted`; the planned object in its state before with other differences is `reverted` with the differences; an existing blocking reason is kept, otherwise the reason is `foreign change`; otherwise `revert-failed` with the differences; an unreadable snapshot is `unknown` (step `revert_unverified`). When the return cannot be sent or proven (step `revert_now_unverified`), the timer returns the change; a `-revert` row that went through unseen ends that wait as well, and the snapshot decides. When the read of `show system commit` right after the own change commit failed, or the connection failed when leaving the configuration mode after that commit, Admin reads it again before the return (limited on its monotonic clock to the time above the 240 s) and takes as its head only the single row right above its own safeguard row with the change comment `netops-change` of this operation, of the write account and with `rollback pending` (step `change_head_adopted`); anything else (a foreign commit, more rows, none) is not taken. When the own change commit cannot be proven after a failed read even then, the timer returns the change (up to 10 minutes). The inverse lines were chosen over `rollback N`: the inverse is measured (undo in the measurement and in the E2E of task 319) and touches only the planned object, while the index N moves with every commit (`rollback 1` is wrong after a confirmation, measured) and a rollback during a pending timer was not measured. The enrollment self-test is left unconfirmed on purpose and returned by the expiry.

**Manual check after `unknown` or `revert-failed`.** Read `show system commit | no-more` and `show configuration interfaces <port> | display set` with the write account. A `rollback pending` row means a timer is still running: wait until it is gone (its expiry returns the state before the newest `commit confirmed`). Then compare the port with the `before` side of the operation record; this comparison always decides. Only an own plain `-revert` row (its row has no `commit confirmed`; written by 1.0.11) shows that the inverse is committed for good. The `-revert` of 1.0.10 was itself a `commit confirmed`: after its expiry its row stays without `rollback pending` although the change has come back (measured live in task 378). A `root via other` row above the own rows means the timer returned the configuration to the state before the newest `commit confirmed`. When the port still differs, set it back by hand in `configure exclusive` with the inverse lines of the plan and a plain `commit comment "..."`, and check it again; never commit while someone else's `rollback pending` row is shown, because the commit would confirm it.

When the change is not confirmed, Junos rolls the configuration back by itself: the measured timer counts whole minutes from the commit row (written at the end of the commit) and expired 0-60 s after them (7-9 s in the Admin runs), and the rollback is committed 55-273 s later as `root via other` (with the broadcast `Commit was not confirmed; automatic rollback complete`). **Waiting and `admin recover` decide by `show system commit` only, never by the clock of the device**: Admin reads it every 10 s (a failed read counts as still pending) and accepts the end of the timer only with that `root via other` row or the own plain `-revert` row of an immediate return above its own safeguard row and no `rollback pending` row; a fresh snapshot then decides (equal to the state before is `reverted`); the wait is limited to 1820 s on the monotonic clock of Admin (the longest timer plus 20 s grace plus 900 s for the minute granularity, the rollback commit and a change commit that restarted the timer: `admin recover` of a change interrupted right after its commit saw the proof 530 s after the expiry of the safeguard commit). `admin recover` sends no commit for an interrupted operation: while its own timer is pending, it waits for that end (the expiry, or an own plain `-revert` row that went through unseen); when the own `-ok`, the own plain `-revert` or a `root via other` row has already ended the timer, it does not wait and a fresh snapshot decides; a timer that ended without the own `-ok`, the own `-revert` or a `root via other` row (an automatic rollback still running, or a commit of someone else that confirmed it) is not taken as removed. The rollback returns the **whole** configuration to the state before the newest `commit confirmed` (measured live in task 378: after the empty safeguard, a change and an inverse each committed with `commit confirmed` and no confirmation, the expiry brought the change back; without the inverse commit it returned the state before the change). Admin's only `commit confirmed` after the empty safeguard is the change, so the rollback returns the state before the change commit, and a commit of someone else in the timer window is returned too; a `commit confirmed` of someone else above the change would make the expiry keep the change, which Admin then reports as `revert-failed`. A confirmation that started before the expiry won the measured race (`automatic rollback failed as other commit triggered during rollback`); Admin starts it only with `confirm_margin_seconds` left before the earliest expiry. A pending timer across a reload was not measured.

**Timing.** A commit took 15-150 s on the measured lab switch (load 15-26). With `commit confirmed 10`, after the change commit Admin needs about 60-90 s for the snapshot, the check account and the final snapshot, and keeps at least 240 s for the confirmation commit, so it ends before the earliest expiry; on a slower device the change is not written or the confirmation is skipped (`no time left to write`, `no time left to confirm`) and the change is returned at once or by the timer. SSH exec reads of a Junos device may take up to 180 s (more than 60 s was seen under load in task 319). A change that is returned by the timer took 16-21 minutes in total on the lab (enrollment included), a confirmed change 6-12 minutes. The device measured an SSH outage of about one hour (banner exchange timeout); Admin then reports the operation as `unknown` or refuses before any change, and `admin recover` settles it later.

Admin refuses, before any write:

| Code | Refused |
|---|---|
| `port_management_interface` | `fxp`, `em`, `me` and `vme` interfaces |
| `port_unsupported_interface` | an interface that is not a physical `ge-`, `xe-`, `et-` or `mge-` port (`irb`, `lo0`, `ae`) |
| `port_missing` | an interface that `show interfaces IF terse` does not know (Junos accepts its configuration without an error, measured) |
| `vlan_missing` | an access VLAN name that is not in the configuration or that `show vlans NAME` does not list (empty answer) |
| `port_not_access` | an access VLAN change of a port without `interface-mode access` |
| `port_uplink` | for a change of the admin state (down **or** up) or of the access VLAN: a trunk (`interface-mode trunk`); only for a change of the access VLAN (`vlan-membership`) also a port that `show ethernet-switching interface IF` does not show with exactly one untagged VLAN (an admin state change is not checked with that command; it has the trunk, LAG member, routed port, LLDP neighbor and learned MAC checks of this table) |
| `port_lag_member` | the same, an aggregated Ethernet member (`ether-options 802.3ad`) |
| `port_routed` | the same, a routed port (`family inet`, `inet6`, `mpls` or `iso`) |
| `port_lldp_neighbor` | an admin state change (down or up) or an access VLAN change of a port with an LLDP neighbor |
| `port_learned_mac` | the same, a port with learned MAC addresses (`show ethernet-switching table interface IF`) |
| `foreign_config_session` | another user in configuration mode, an uncommitted change of someone else, or a pending `commit confirmed` of someone else (also one that appears between the prechecks and the safeguard commit: the operation then ends `rejected` with this code) |
| `write_account_privilege` | a write account without the permissions `configure`, `view` and `view-configuration` |

Configuration that reaches the port from elsewhere (an `interface-range` with the port or with a `member-range`, `groups` with interfaces, a `deactivate` statement of the port) is outside the profile and refused. A leftover `netops-` commit confirmed is refused until it expires. Enrollment (`admin enroll --device D --probe ge-0/0/2`) sets the description of the probe interface to `netops-enroll-<hex>` and lets the timer return it.

## FortiADC pool member

On FortiADC, Admin changes only real-server pool members. Since 1.0.10 they go through the same path as the other platforms: MCP `admin_preview`, `admin_apply` (with `expected_plan_sha256`), `admin_undo_preview`, `admin_doctor` and `admin_status`, and the operator commands `preview`, `apply`, `undo`, `enroll`, `doctor`, `status` and `recover`. Each change is planned from a fresh snapshot, needs a valid enrollment, is read back by the separate check account and is recorded in the journal and the Admin operation log with its `request_id`. The measured scope is FortiADC-KVM 7.6.7 build0676, standalone (profile `fortiadc-pool-member.json`, exact build).

The table is `load-balance pool/pool_member`; the key is `POOL:MEMBER`, the pool name and the number of the pool member entry, for example `LAB_POOL_SMTP:2`. Attributes: `status` (`enable`, `disable` or `maintain`; the only attribute an update changes), `real-server`, `pool-member-service-port` (default 80), `pool-member-cookie` and `pool-member-weight` (default 1). The device spells the last three with underscores (`pool_member_service_port`, ...); Admin translates them. A member created without a cookie gets the cookie `rsN` from the device (N is the member number, measured on 7.6.7 build0676); Admin treats `rsN` on member N as that default, so do not send it explicitly.

- **Status** (`op: update`, `changes: {"status": "disable"}`): before any write, every virtual server that uses the pool must keep at least one enabled member whose health check is up (`diagnose server-load-balance vs_stat`, read with the write account); otherwise the request is refused with `no_healthy_member`. A virtual server that selects pools by content routing or schedule is refused, because the pool use cannot be evaluated.
- **Add** (`op: create`, `real-server`, optional `pool-member-service-port`, and `status` `disable` or `maintain`): a new member is never created enabled; enable it with a separate update once its health check is up. Refused before any write when the member number is used, the real server is not configured, or the same real server with the same port is already a member.
- **Remove** (`op: delete`, empty `changes`): only a member with status `disable` or `maintain`, never the last member of a pool, and never a member with settings outside the profile.

Preview example (MCP `admin_preview` arguments; `admin_apply` takes the same and `expected_plan_sha256`):

```json
{"device": "adc-a", "table": "load-balance pool/pool_member", "op": "update", "key": "POOL_WEB:2",
 "changes": {"status": "disable"}, "reason": "patching web2", "user_request": "take web2 out of the pool",
 "request_id": "adc-web2-off-0001"}
```

**Return of an unverified change (platform property, not a device safeguard).** FortiADC 7.6.7 offers Admin no on-device timed return: its CLI has no `automation-stitch`, scheduler or cron (all answer `Parsing error`, read on VM220, task 306). The FortiADC documentation describes alert policies of type `schedule` with a CLI script action, which might serve as one; this was not measured, because measuring it needs device writes outside the approved test pool, so Admin does not use it and does not claim it. Admin therefore returns an unverified change itself, in the same run: when the write, the readback of the write account or the readback of the check account fails, it writes the inverse (the previous status, the delete of a new member, the create of a removed member from its read settings) and verifies the snapshot against the state before. The result is `reverted` when that holds, `revert-failed` or `unknown` (the device is blocked) otherwise; preview names this as `return_mechanism`, and the journal records `compensation_*` steps and a `safeguard` with `fire_at` `none`. **If the Admin process, the host or the management path is lost after the write, nothing on the device returns the change.** Run `admin recover`: it returns an interrupted change that was not confirmed in the same way. Enrollment uses the same mechanism: `admin enroll --device adc-a --probe POOL:MEMBER:REAL_SERVER:PORT` creates an unused member number disabled (a real server and a port that are not yet a member of that pool), lets the compensation remove it and verifies the pool before and the check account; it proves the write, readback and compensation path, not an on-device timer.

**Not covered on FortiADC:** Admin runs no auditor rules there (they need the exported full configuration and its context, `auditor run --platform fortiadc`); preview reports this under `audit_unevaluated` and doctor as `cannot verify`. Admin does not read other administrator sessions (`foreign_sessions_unreadable`). The snapshot Admin plans against is composed of `show load-balance pool`, `show load-balance virtual-server`, `show load-balance real-server` and `show system admin` (with the firmware from `get system status`); a change elsewhere in the configuration is not seen by the postcheck. The write account sees exactly the configured administrators (`accounts`, or the write and the check login); any other administrator refuses the change and blocks the device, as on FortiOS.

The write login must be a FortiADC system administrator (`is-system-admin yes`), limited by a trusted host to the Admin host; a login without it is refused by the health precheck. The check login is a second, read-only login (the Helper read profile) with the trusted host of the Admin host; it reads the pool with `show load-balance pool POOL` and its identity with `get system status`. See [Accounts and least privilege](../components/netops-helper/docs/read-only-accounts.md).

**Deprecated operator commands.** `pool-member`, `pool-member-add` and `pool-member-remove` still work unchanged (same options, JSON record and exit codes: 0 confirmed or unchanged, 3 rejected, 4 rolled_back, 7 unknown), but they are deprecated: they need no enrollment, have no preview or `plan_sha256`, and write no journal or Admin operation record; they print a deprecation line on standard error. Use `preview`, `apply` and `undo` with the table above instead. The command grammar of the old commands is in the [FortiADC contract](fortiadc-f1-contract.md#admin-pool-member-add-and-pool-member-remove), the measured scope in [FortiADC bounds](verified-support.md#fortiadc-bounds).

## MCP tools

The HTTPS MCP endpoint exposes seven Admin tools. There is no MCP tool to undo a change, unblock a device, cancel a safeguard or edit a plan; undo and unblock are the operator commands above. `admin_undo_preview` only shows what an undo would do; the undo itself stays the operator command `admin undo`.

| Tool | Arguments | Current behavior |
|---|---|---|
| admin_doctor | `device`, optional `local` (default `false`) | Readiness report without a change: `ready`, and `checks` whose status is `ok`, `missing`, `refused`, `skipped`, `warning` or `cannot verify` (the last two leave `ready` unchanged); `operations` maps each table of the platform to its operations, or to `not measured on this firmware`, for the firmware read from the device |
| admin_preview | `device`, `table`, `op`, `key`, `changes`, `reason`, `user_request`, `request_id` | Every check of apply without a change: `result` is `ready`, `rejected` with `reasons`, or `known-request` with the `change_id` of an earlier operation of the same `request_id`; on FortiADC also `return_mechanism` |
| admin_apply | as admin_preview, optional `expected_plan_sha256` | One change behind the device safeguard (on FortiADC, which has none, behind the compensating return in the same run, see [FortiADC pool member](#fortiadc-pool-member)); `result` is `confirmed`, `reverted`, `rejected`, `unknown` or `revert-failed`. With `expected_plan_sha256` (the `plan_sha256` of the approved `admin_preview`) a fresh plan that differs is `rejected` with `plan_changed` before any write |
| admin_undo_preview | `change_id`, `reason` | Every check of the undo of a confirmed operation without a change, as admin_preview plus `undo_of` and `request_id` (`undo-CHANGE_ID`); after an undo has run it is `rejected` with `undo_already_done` |
| admin_status | `change_id` or `request_id` | The stored operation record; `unknown-operation` when nothing matches, also for a call with neither argument |
| admin_schema_preview | `device`, `operations`, `reason`, `user_request`, `request_id` | Checks of a schema transaction without a change |
| admin_schema_apply | as admin_schema_preview | A schema transaction behind the device safeguard; it has no `expected_plan_sha256` |

`op` is `create`, `update` or `delete`. `key` has at most 128 characters and `table` at most 64. `changes` maps at most 16 attribute names (a lowercase letter followed by up to 63 lowercase letters, digits or hyphens) to a string, an integer, a list of strings or `null` to remove the attribute; for `delete` it is empty. `reason` has at most 500 characters and `user_request` at most 4000. `request_id` has 8–64 letters, digits, `.`, `_`, `:` or `-`. A schema transaction has 1–32 `operations`, each an object with exactly `path`, `scope`, `owners`, `op` and `changes`; it requires a FortiOS device with a configured operator `schema` binding and is otherwise rejected with `schema transactions require a configured operator binding`. A binding names its schema library and rollback calibration by absolute file paths inside the container, and NetOps 1.0 has no supported way to place those files, so schema transactions are not a supported workflow in NetOps 1.0.

**Binding apply to an approved preview.** `expected_plan_sha256` (MCP `admin_apply`, operator command `admin apply --expect-plan-sha256`) is 64 lowercase hexadecimal characters; any other value is `rejected`. Apply still plans again from a fresh snapshot; when the `plan_sha256` of that plan differs from the expected one, the change is refused before the operation is recorded and before any device write, with `reason_codes` `["plan_changed"]` and `reason_details` `[{"code": "plan_changed", "expected": ..., "actual": ...}]`. The refusal counts toward the budget of rejected requests like every other refusal and creates no Admin operation record; the MCP request and response of `admin_apply` and the operator preflight record of `admin apply` are audited as for every call. The `plan_sha256` of a profile request covers the target - the device alias from the configuration, the platform and the firmware (no secrets; FortiOS and Arista EOS read the firmware from the fresh snapshot, Junos from its `set version` line (verified against the live `show version` before any write), ExtremeXOS, Cisco IOS and IOS XE use the configured version, which Admin verifies against the live `show version` before any write) - together with the commands, the inverse and the predicted object before and after, so a preview approved for one device or firmware never matches the same change on another device or after a firmware change, while a change elsewhere in the configuration does not break the binding. The reason of the refusal names these causes and asks for a new preview. Since 1.0.10 the target is part of the hash: a `plan_sha256` from an Admin 1.0.9 preview is refused with `plan_changed` after the upgrade (run a new preview); stored operation records of earlier versions keep their content-only hash and stay readable for verify, recovery and undo. The parameter is not part of the request identity: a repeated `request_id` returns the operation it started, whatever hash is sent (a malformed hash is still refused). Without the parameter apply behaves as in 1.0.8. Schema transactions have no such binding: their `plan_sha256` depends on the snapshot and the `request_id`, so `admin_schema_apply` has no `expected_plan_sha256` and `admin apply --expect-plan-sha256` refuses a schema transaction.

## Safety and results

Safeguards last 60–900 seconds; the confirmation margin is at least 15 seconds and at most the safeguard interval minus 15 seconds. Protected objects and their references are refused. Existing per-device/hour, daily, rejection, command and journal limits remain enforced. The per-device `legacy_ssh` exception (`rsa-sha1` or `rsa-sha1-dh14`) retains normal host-key pinning.

Rejected operations, unknown outcomes and reverted/failed returns are MCP errors. Structured results, reasons, request/change IDs and device blocks are preserved. A successful status lookup may report a previously failed operation. A `change_id` or `request_id` that matches no operation is a failed lookup, not an operation with an unknown outcome, and says nothing about the device: the MCP tool `admin_status` returns `unknown-operation` with the reason `no operation matches` as an MCP error, and the operator command `admin status` prints `"result": "rejected"` with the same reason and exits with status 3. Both forms mean the same. Never automatically retry unknown writes: inspect the actual device and journal and use explicit recovery.

The mandatory gateway audit records HTTPS MCP requests before dispatch and responses before delivery. Offline Admin operator workflows run while the gateway is stopped. Before each workflow, a short process under the gateway UID durably records an operator-preflight event with an allowlisted workflow name; device aliases, reasons and other argument values are not copied into that event. The Admin engine then records the operation in its private operations.jsonl and change journal. The preflight event records intent to start, not successful completion; inspect the private operation record and actual device state for the outcome. The deprecated FortiADC commands `pool-member`, `pool-member-add` and `pool-member-remove` are the exception (FortiADC changes through `apply` are recorded like any other): the preflight event names the workflow `other`, and the commands write no operations.jsonl or change-journal entry; their only record is the JSON record they print, so keep that output.

Missing or invalid gateway audit configuration, an unwritable audit, a failed durable write or a detected incomplete final local record refuses the workflow. Existing complete JSONL records are not revalidated by this preflight, and local audit does not prove freedom from privileged tampering. The diagnostic reports only the exception type. MCP calls are refused before dispatch when their gateway audit cannot be written. Admin checks its private operation log before device writes.

Optional legacy engine export-status files are not provisioned by the product and are absent from the example. No legacy exporter is required in the unified product. A result with no legacy exporter records independent Admin-log delivery as not configured, never acknowledged. If an operator configures a legacy export-status file, unreadable, stale or blocked status still refuses changes. Notifications use trusted HTTPS; redirects and failed TLS verification are refused.


Admin refusal responses include `reason_codes` alongside the existing text. `reason_codes` is an aggregate of categories for the refusal, not a list paired by index with `reasons`; several reasons may share one code. Every preview and apply refusal (and the ready preview, where it is empty) carries `reason_details`, and so does an operation that ends `rejected` after it was recorded (MCP result and CLI record: the enrollment notification could not be sent, the device clock could not be read, a PoE cycle found too little time left before its safeguard fires, or `recover` found it interrupted before any device change); `reason_details` is a list that is empty except for budget refusals, which give the `budget` (`rejected_hour`, `journal_records`, `device_hour`, or `global_day`), `plan_changed`, which gives the `expected` and `actual` plan hash, `undo_already_done` from an undo preview after a repeated undo request, which gives the `change_id` of the undo operation, and `safeguard_margin_insufficient` before a PoE cycle is recorded, which gives `cycle_seconds`, `confirm_margin_seconds`, `available_seconds` and `required_safeguard_seconds`. These codes never authorize an automatic retry; unknown codes also require stopping automatic action.

| Code | Operator action |
| --- | --- |
| `device_blocked` | Investigate and unblock manually. |
| `request_id_reused` | Check the request identity; do not start a second operation. |
| `undo_already_done` | Inspect the existing undo operation before taking further action. |
| `plan_changed` | The device changed since the approved preview; nothing was changed. Run a new preview and have it approved again. |
| `enrollment_required` | Complete a successful enrollment self-test for this device and configuration. |
| `notification_pending` | Check delivery and operation status; the change may already be complete. |
| `operation_unfinished` | Inspect the operation and recover as appropriate. |
| `budget_exhausted` | Inspect the named budget and resolve its limit. |
| `state_unreadable` | Inspect and repair the journal before proceeding. |
| `notification_unavailable` | The enrollment notification could not be sent; nothing was changed. Check the notification channel. |
| `device_clock_unreadable` | The device clock could not be read; no safeguard was installed and nothing was changed. Check the device and the account. A PoE cycle reads the clock again after its safeguard is installed. If that read fails, the safeguard is removed again and inline power is not touched. |
| `profile_not_measured` | End-to-end Admin/safeguard execution is not measured for the requested profile; nothing was read or changed. `opt_in` does not bypass this guard. The measured `firewall service custom` profile no longer receives this refusal. |
| `interrupted_before_mutation` | `recover` found the operation interrupted before any device change; submit a new request if the change is still wanted. |
| `port_protected`, `port_management_vlan`, `port_uplink`, `port_lag_member`, `port_lldp_neighbor`, `port_learned_mac` | The ExtremeXOS, EOS, IOS, IOS XE, NX-OS or Junos port is protected or in use; nothing was changed. Choose another port or change it by hand after checking ([port admin state](#extremexos-port-admin-state-and-poe-cycle)). |
| `port_usage_unreadable` | The LLDP, CDP, FDB, trunk or MAC-table answer of the switch, the EOS or NX-OS interface status or the IOS management interface was not recognised; nothing was changed. Check the switch and the account. |
| `port_missing`, `port_not_access` | The Junos interface does not exist on the switch, or it is not an access port for an access VLAN change; nothing was changed ([Junos](#juniper-junos-interface-description-admin-state-and-access-vlan)). |
| `port_action_not_measured` | Port admin state and PoE cycle are measured only on ExtremeXOS 33.7.1.6; nothing was changed. |
| `poe_not_capable`, `poe_unsupported`, `poe_disabled`, `poe_state_unreadable` | The PoE cycle is not possible on this port or switch; nothing was changed. |
| `safeguard_margin_insufficient` | The safeguard of the switch leaves no time for a whole PoE cycle and its confirm margin; inline power was not touched. Raise `safeguard_seconds` of the device to `required_safeguard_seconds` from `reason_details` ([safeguard margin](#extremexos-port-admin-state-and-poe-cycle)). |
| `action_only_table` | The table is changed only by its own operation (`inline-power`: the operator command `admin poe-cycle`, see [PoE cycle](#extremexos-port-admin-state-and-poe-cycle)). |
| `action_unsupported` | The operation does not exist for this device platform. |
| `undo_not_applicable` | The operation has no undo (a PoE cycle leaves the configuration as before). |
| `write_account_privilege` | The EOS, IOS or IOS XE write account does not log in with privilege 15, or the Junos write account lacks `configure`, `view` or `view-configuration`; nothing was changed. Configure `username ... privilege 15` (EOS also `aaa authorization exec default local`; [EOS](#arista-eos-interface-description-admin-state-and-access-vlan), [IOS](#cisco-ios-and-ios-xe-interface-description-admin-state-and-access-vlan)). |
| `archive_not_configured` | The IOS configuration archive that the revert timer needs is not configured; nothing was changed. Configure `archive` with `path` and `maximum` ([IOS](#cisco-ios-and-ios-xe-interface-description-admin-state-and-access-vlan)). |
| `rollback_timer_pending` | A revert timer (`configure terminal revert timer`) of someone is pending on the IOS device; nothing was changed. The timer is global: wait until it ends or ask its owner. |
| `port_ip_address` | The IOS interface or one of its subinterfaces carries an IPv4 address; its admin state is not changed by Admin. |
| `vlan_reserved` | The access VLAN is reserved (1002–1005 on IOS and IOS XE, 3968–4094 on NX-OS); nothing was changed. |
| `foreign_config_session` | Someone else has an open EOS or NX-OS configuration session or a pending EOS commit timer, or on Junos is in configuration mode, holds an uncommitted change or a pending `commit confirmed`; nothing was changed. Wait until it ends or ask its owner. |
| `vlan_missing` | The access VLAN does not exist on the EOS, IOS, IOS XE or NX-OS switch (EOS and IOS would create it silently, NX-OS would accept it and leave the port inactive), or the Junos VLAN name is unknown; nothing was changed. |
| `port_management_interface`, `port_unsupported_interface`, `port_routed` | The EOS, IOS, IOS XE, NX-OS or Junos interface is a management interface, not an Ethernet port, or a routed port (on IOS also: an access VLAN on a router image); nothing was changed. |
| `scheduler_feature_disabled` | `feature scheduler` is not enabled on the NX-OS switch, which the timed return needs; nothing was changed. Its administrator enables it once and leaves it enabled ([NX-OS](#cisco-nx-os-interface-description-admin-state-and-access-vlan)). |
| `rollback_in_progress` | A rollback or configure replace is running on the NX-OS switch; nothing was changed. Wait until it ends. |
| `no_healthy_member` | The FortiADC status change would leave a virtual server of the pool without an enabled member whose health check is up; nothing was changed. Bring another member up first ([FortiADC pool member](#fortiadc-pool-member)). |
| `unspecified_refusal` | Read the existing reason and investigate. |


`admin doctor --device firewall-a --local` (or `admin_doctor` with `local: true`) performs only local checks, without contacting or changing the device. It may write locally for writability probes, audit or initialization. The response has `scope: local`, `local_ready`, `remote_readiness: unverified`, `ready: false`, `firmware: null` and empty `operations`. CLI exit 0 means local checks passed, not that remote readiness was verified. Run full doctor before relying on device readiness.
