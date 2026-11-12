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

Enrollment performs a real temporary device change and deliberately lets the on-device safeguard return it. Reserve a genuinely unused subnet for the FortiOS probe; the documentation subnet below is only an example and must be reviewed for the target. Enrollment can take the full safeguard interval and verification time. Keep this operator command running until it reports a final outcome.

~~~sh
docker compose stop
docker compose run --rm netops admin enroll --device firewall-a --probe 192.0.2.252/30
docker compose run --rm netops admin doctor --device firewall-a
docker compose up -d --wait
~~~

Successful enrollment reports `"enrollment": "valid"` with `"result": "reverted"` and reason `"enrollment self-test"`: the probe must be gone, the safeguard absent and notification sent. Doctor then reports `"ready": true`. An exit code alone is insufficient; inspect the structured result. If enrollment is not valid or doctor is not ready, stop and resolve the reported cause before requesting a change. Re-enroll after changing the bound device configuration, firmware, account identities, profiles or notification settings.

Doctor also checks whether the write and check accounts have more rights than their role needs. Each account reads only its own entry with `show system admin "<login>"` and, for the check account, its own profile with `show system accprofile "<profile>"`; doctor keeps only the profile fields and never reports password, `ENC` or certificate lines. The checks `write account rights` and `check account rights` report `warning` for a FortiOS `super_admin` or `prof_admin` write account before 8.0.1 (on 8.0.1 and later the webhook safeguard needs `super_admin`), for a FortiOS check account with `super_admin`, `prof_admin`, a `read-write` group or `cli-config enable`, and for a FortiADC check account with `is-system-admin yes` or a `read-write` area; a FortiADC write account may be a system administrator, which `pool-member` needs. The warning names the row of [Accounts and least privilege](../components/netops-helper/docs/read-only-accounts.md) that lists the rights of that role; the FortiADC row `Admin check` there is not measured, so for a FortiADC check account the warning rests only on the entry and profile the account reads. They report `cannot verify` with the reason or the exact device answer when the entry or the profile cannot be read, for example a wildcard, RADIUS, TACACS+ or VDOM administrator without a local profile (an entry that is not found), a check account without `cli-show` (`Unknown action 0`), a `custom` group, or a profile the account does not see; a refusal line that may hold a secret is reported without the rest of the line. On FortiOS neither status changes `ready` or the exit code. On FortiADC doctor still refuses with `platform 'fortiadc' has no plan and apply adapter`, as before, with the exit code of a refusal and no `ready`; the reasons after it list the result of `credentials` and of the two checks, for example `check account rights: warning (...)`. The `warning` and `cannot verify` results are verified by tests against simulated devices; on real devices (FortiOS 7.6.8, FortiOS 8.0.2, FortiADC 7.6.7) only the result `ok` was verified.

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

Preview reads the device and returns the proposed commands, prediction and refusal reasons without making a change. Continue only when `result` is `ready` and the person has reviewed the plan. Then call `admin_apply` with the same arguments. Apply plans again from a fresh snapshot and uses the device safeguard and independent check account; preview is not a stored executable plan.

`admin_doctor`, `admin_preview`, `admin_apply` and the operator commands `admin doctor` and `admin enroll` read the device configuration over SSH with a 180-second limit that includes the host-key check (later SSH queries are limited to 60 seconds and interactive logins to 30 seconds). When the device does not answer, these calls return their refusal only after about 180 seconds. Set the request timeout of the MCP client above 180 seconds. A client timeout does not prove that the call was cancelled: the operation can still complete, and the audit can hold its response or an interrupted or pending record. Inspect `admin_status` and the actual device first, and never repeat a write automatically. The Admin worker handles one MCP request at a time; further Admin calls wait until the running one ends. While a long operator command such as `admin enroll` runs, `docker ps` can show its `docker compose run` container as `unhealthy`: the service healthcheck also runs in that container, which has no gateway (see the [quickstart](quickstart-1.0.md)). This does not affect the command; judge it by its final structured result.

A completed change must report `result: confirmed`, successful notification and no blocking reason. Retain the returned `change_id` and read it through `admin_status` using `{"change_id": "CHANGE_ID_FROM_RESPONSE"}`. Inspect the actual object through the independent read-only account. Repeating an already used `request_id` returns its existing operation; it does not authorize another write. For an unknown or interrupted result, inspect status and the actual device before any operator recovery.

## Return the test change as an operator

Undo is an explicit operator action, not an MCP tool. Use the actual change ID from the confirmed operation:

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
- **Undo limits.** `admin undo` runs once per change, under the fixed request ID `undo-CHANGE_ID`, so repeating it never repeats the write. Repeating exactly the same undo request (same reason) returns the stored result of the first undo. An undo of the same change with a different request (another reason) is refused with exit code 3 (rejected, like every refused request) and the text `undo of this change has already been performed; after a reverted change remove the object with regular administration`; nothing is sent to the device. Development builds printed `request_id was already used for a different request`, which says nothing about the cause. When the undo ended `reverted` (the safeguard restored the object), the object is still there and cannot be undone again; the profile has no `delete` operation, so remove such a policy through the normal administration. A genuine reuse of a request ID by another request keeps the text `request_id was already used for a different request`.
- **Provisional profile.** The profile `firewall policy` is provisional. Create and undo of a policy were measured on FortiOS 7.6.8 build3744 and 8.0.2 build0251, and the cleanup was verified (configuration equal to the configuration before, HA pair in sync, `admin recover` found nothing). On 8.0.2 the run with the whole management path blocked was recorded only once, with NetOps reaching the device through a translated (DNAT) address, and its repeat was not completed.
- **What was measured and what was only tested.** Measured live: on FortiOS 8.0.2 build0251 (FortiGate 80F active-passive HA pair, 2026-11-02) the main path `admin apply` with confirmation and revert, the attacks that remove the check account (`PUT`, `DELETE` and `POST` inverses), SIGKILL after `change_applied` followed by `admin recover`, and the precheck refusal; on FortiOS 7.6.8 build3744 (FortiGate 60F, `cli-script` safeguard) enrollment, a create and its undo. Verified only by automated tests against a simulated device, not on a real device: recovery after a partial installation of the safeguard (status `finished` with result `unknown` and `safeguard not verified`) through `admin recover`. Treat this recovery as untested on hardware and read the steps of `admin status` and the device afterwards.
- When the check account loses the device after the change, the safeguard restores the previous policy at `trigger-datetime` and the result is `reverted`; after a crash of NetOps after `change_applied`, `admin recover` ends `reverted`; when the whole management path is lost after the change, the result is `unknown` and the device stays blocked until the `netops-sg-` objects are removed and `admin unblock` runs. The measurements are in [verified support](verified-support.md#fortios-bounds).
- A Fortinet Technical Tip states that from FortiOS 8.0.1 build0185 auto-script, which the safeguard's `cli-script` action runs, allows only information-gathering commands (get, diagnose), while the 8.0.2 Administration Guide still shows CLI script examples with configuration commands. On a FortiGate 80F with 8.0.2 build0251 the stitch fired, but every configuration line was refused with `Unknown action or command is unavailable in auto-script`, and the probe address was still present after `trigger-datetime`. This is an observed refusal on the measured build and the statement of the Technical Tip, not a measurement of every 8.0.x build, so Admin does not rely on the `cli-script` safeguard from 8.0.1; on these builds Admin uses the webhook safeguard ([Admin safeguard on FortiOS 7.6 and 8.0](verified-support.md#admin-safeguard-on-fortios-76-and-80), with the Fortinet sources).

## FortiADC pool member

On FortiADC, Admin changes only real-server pool members, through three operator commands of `netops-admin` on the command line; there is no MCP tool and no `admin_apply` path for FortiADC.

- `pool-member` sets the status (`enable`, `disable` or `maintain`) of one existing pool member.
- `pool-member-add` creates one new pool member, always with `status disable`; enable it afterwards with `pool-member --status enable` once its health check is up. It is refused before any write when the pool is not listed, the member number is already used, the real server is not configured, or the same real server with the same port is already a member.
- `pool-member-remove` deletes one member whose status is `disable` or `maintain`. It is refused before any write for an enabled member, the last member of a pool and a member with settings that cannot be restored.

Options (all required; the operator command supplies the Admin configuration itself):

- `--device`: the name of a configured device with platform `fortiadc`.
- `--pool`: the pool name.
- `--member`: the number of the pool member entry.
- `--status` (`pool-member` only): `enable`, `disable` or `maintain`.
- `--real-server` and `--service-port` (`pool-member-add` only): the configured real server and its port.

Run them from the NetOps directory with the instance stopped, as the other operator commands. Add member 3 to pool `POOL_WEB`; it is created disabled:

```sh
docker compose stop
docker compose run --rm netops admin pool-member-add --device adc-a --pool POOL_WEB --member 3 --real-server RS_WEB3 --service-port 80
docker compose up -d --wait
```

Check on the FortiADC that the health check of the new member is up, then enable it:

```sh
docker compose stop
docker compose run --rm netops admin pool-member --device adc-a --pool POOL_WEB --member 3 --status enable
docker compose up -d --wait
```

To take the member out later, disable it first and then remove it:

```sh
docker compose stop
docker compose run --rm netops admin pool-member --device adc-a --pool POOL_WEB --member 3 --status disable
docker compose run --rm netops admin pool-member-remove --device adc-a --pool POOL_WEB --member 3
docker compose up -d --wait
```

Each command prints one JSON record and ends with exit code 0 when the change is `confirmed` or the member already has the requested status (`unchanged`), 4 when it was returned and the pool equals the state before (`rolled_back`), and 7 when the result is `unknown`; read the pool on the device then. A refusal before any write ends with exit code 3 (`rejected`) and its reasons.

The write login must be a FortiADC system administrator (`is-system-admin yes`), limited by a trusted host to the Admin host; a login without it is refused by the precheck. See the row Admin `pool-member` in [Accounts and least privilege](../components/netops-helper/docs/read-only-accounts.md). The command grammar, prechecks and readbacks are in the [FortiADC contract](fortiadc-f1-contract.md#admin-pool-member-add-and-pool-member-remove), the measured scope in [FortiADC bounds](verified-support.md#fortiadc-bounds).

## MCP tools

The HTTPS MCP endpoint exposes six Admin tools. There is no MCP tool to undo a change, unblock a device, cancel a safeguard or edit a plan; undo and unblock are the operator commands above.

| Tool | Arguments | Current behavior |
|---|---|---|
| admin_doctor | `device`, optional `local` (default `false`) | Readiness report without a change: `ready`, and `checks` whose status is `ok`, `missing`, `refused`, `skipped`, `warning` or `cannot verify` (the last two leave `ready` unchanged); `operations` maps each table of the platform to its operations, or to `not measured on this firmware`, for the firmware read from the device |
| admin_preview | `device`, `table`, `op`, `key`, `changes`, `reason`, `user_request`, `request_id` | Every check of apply without a change: `result` is `ready`, `rejected` with `reasons`, or `known-request` with the `change_id` of an earlier operation of the same `request_id` |
| admin_apply | as admin_preview | One change behind the device safeguard; `result` is `confirmed`, `reverted`, `rejected`, `unknown` or `revert-failed` |
| admin_status | `change_id` or `request_id` | The stored operation record; `unknown-operation` when nothing matches, also for a call with neither argument |
| admin_schema_preview | `device`, `operations`, `reason`, `user_request`, `request_id` | Checks of a schema transaction without a change |
| admin_schema_apply | as admin_schema_preview | A schema transaction behind the device safeguard |

`op` is `create`, `update` or `delete`. `key` has at most 128 characters and `table` at most 64. `changes` maps at most 16 attribute names (a lowercase letter followed by up to 63 lowercase letters, digits or hyphens) to a string, an integer, a list of strings or `null` to remove the attribute; for `delete` it is empty. `reason` has at most 500 characters and `user_request` at most 4000. `request_id` has 8–64 letters, digits, `.`, `_`, `:` or `-`. A schema transaction has 1–32 `operations`, each an object with exactly `path`, `scope`, `owners`, `op` and `changes`; it requires a FortiOS device with a configured operator `schema` binding and is otherwise rejected with `schema transactions require a configured operator binding`. A binding names its schema library and rollback calibration by absolute file paths inside the container, and NetOps 1.0 has no supported way to place those files, so schema transactions are not a supported workflow in NetOps 1.0.

## Safety and results

Safeguards last 60–900 seconds; the confirmation margin is at least 15 seconds and at most the safeguard interval minus 15 seconds. Protected objects and their references are refused. Existing per-device/hour, daily, rejection, command and journal limits remain enforced. The per-device `legacy_ssh` exception (`rsa-sha1` or `rsa-sha1-dh14`) retains normal host-key pinning.

Rejected operations, unknown outcomes and reverted/failed returns are MCP errors. Structured results, reasons, request/change IDs and device blocks are preserved. A successful status lookup may report a previously failed operation. A `change_id` or `request_id` that matches no operation is a failed lookup, not an operation with an unknown outcome, and says nothing about the device: the MCP tool `admin_status` returns `unknown-operation` with the reason `no operation matches` as an MCP error, and the operator command `admin status` prints `"result": "rejected"` with the same reason and exits with status 3. Both forms mean the same. Never automatically retry unknown writes: inspect the actual device and journal and use explicit recovery.

The mandatory gateway audit records HTTPS MCP requests before dispatch and responses before delivery. Offline Admin operator workflows run while the gateway is stopped. Before each workflow, a short process under the gateway UID durably records an operator-preflight event with an allowlisted workflow name; device aliases, reasons and other argument values are not copied into that event. The Admin engine then records the operation in its private operations.jsonl and change journal. The preflight event records intent to start, not successful completion; inspect the private operation record and actual device state for the outcome. FortiADC `pool-member`, `pool-member-add` and `pool-member-remove` are the exception: the preflight event names the workflow `other`, and the commands write no operations.jsonl or change-journal entry; their only record is the JSON record they print, so keep that output.

Missing or invalid gateway audit configuration, an unwritable audit, a failed durable write or a detected incomplete final local record refuses the workflow. Existing complete JSONL records are not revalidated by this preflight, and local audit does not prove freedom from privileged tampering. The diagnostic reports only the exception type. MCP calls are refused before dispatch when their gateway audit cannot be written. Admin checks its private operation log before device writes.

Optional legacy engine export-status files are not provisioned by the product and are absent from the example. No legacy exporter is required in the unified product. A result with no legacy exporter records independent Admin-log delivery as not configured, never acknowledged. If an operator configures a legacy export-status file, unreadable, stale or blocked status still refuses changes. Notifications use trusted HTTPS; redirects and failed TLS verification are refused.


Admin refusal responses include `reason_codes` alongside the existing text. `reason_codes` is an aggregate of categories for the refusal, not a list paired by index with `reasons`; several reasons may share one code. Every preview and apply refusal (and the ready preview, where it is empty) carries `reason_details`, and so does an operation that ends `rejected` after it was recorded (MCP result and CLI record: the enrollment notification could not be sent, the device clock could not be read, or `recover` found it interrupted before any device change); `reason_details` is a list that is empty except for budget refusals, which give the `budget` (`rejected_hour`, `journal_records`, `device_hour`, or `global_day`). These codes never authorize an automatic retry; unknown codes also require stopping automatic action.

| Code | Operator action |
| --- | --- |
| `device_blocked` | Investigate and unblock manually. |
| `request_id_reused` | Check the request identity; do not start a second operation. |
| `undo_already_done` | Inspect the existing undo operation before taking further action. |
| `enrollment_required` | Complete a successful enrollment self-test for this device and configuration. |
| `notification_pending` | Check delivery and operation status; the change may already be complete. |
| `operation_unfinished` | Inspect the operation and recover as appropriate. |
| `budget_exhausted` | Inspect the named budget and resolve its limit. |
| `state_unreadable` | Inspect and repair the journal before proceeding. |
| `notification_unavailable` | The enrollment notification could not be sent; nothing was changed. Check the notification channel. |
| `device_clock_unreadable` | The device clock could not be read; no safeguard was installed and nothing was changed. Check the device and the account. |
| `interrupted_before_mutation` | `recover` found the operation interrupted before any device change; submit a new request if the change is still wanted. |
| `unspecified_refusal` | Read the existing reason and investigate. |


`admin doctor --device firewall-a --local` (or `admin_doctor` with `local: true`) performs only local checks, without contacting or changing the device. It may write locally for writability probes, audit or initialization. The response has `scope: local`, `local_ready`, `remote_readiness: unverified`, `ready: false`, `firmware: null` and empty `operations`. CLI exit 0 means local checks passed, not that remote readiness was verified. Run full doctor before relying on device readiness.
