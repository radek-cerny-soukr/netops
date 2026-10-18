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

Admin write and independent check accounts must differ. The check account verifies device identity and readback independently. FortiOS administrator visibility is bounded by the enrolled accounts. ExtremeXOS also needs exact `firmware` and the explicit create/configure account fingerprint; implicit accounts are not proven.

## Blocked device or undelivered notification

Admin blocks a device when an operation ends with result `unknown` or `revert-failed`, or with a blocking reason: `administrator table`, `foreign change`, `not persisted`, `foreign change during save`, `saved configuration unverified`, `postcheck rejected`, `snapshot incomplete`, `snapshot scope unsupported`, `snapshot unreadable` or `snapshot firmware mismatch`. Every further preview, apply or enrollment for that device is then refused with `the device is blocked (REASON, operation CHANGE_ID); a person must investigate and unblock it`, and doctor reports the device state as refused. A finished operation whose notification is still `pending`, `failed` or `sending` also refuses new operations on its device: `the notification of operation CHANGE_ID was not delivered; run notify-retry, or a person unblocks the device after checking the notification channel`.

These operator commands run with the instance stopped, like `recover` above:

- `admin notify-retry --change-id CHANGE_ID` sends the notification of that finished operation again unless it was already sent; it needs a configured notification.
- `admin unblock --device firewall-a --reason "TEXT"` is for a person who has inspected the operation record and the actual device. It lifts the block, clears the stored administrator-account baseline of the device and marks its undelivered notifications as `waived`. The private Admin operation log records only the length of the reason, not its text. The command prints a JSON object with `device` and `unblocked`, which is `false` when there was nothing to lift or waive.

Inside NetOps, the operator commands `apply`, `preview`, `doctor`, `enroll`, `status`, `recover`, `notify-retry`, `unblock` and `undo` receive `--config` with the private Admin configuration automatically; `admin enroll --help` and the other subcommand help pages still list `--config` as required, but the documented commands omit it. `plan`, `verify`, `schema-plan` and `schema-verify` are offline engine commands that take explicit file paths readable by the Admin UID, and `apply` and `preview` also need a `--request` file. NetOps 1.0 places Admin operator files only through `configure admin` (JSON on standard input), so these engine commands have no supported way to receive their input files and are not a supported operator workflow in NetOps 1.0; preview and apply changes with the MCP tools `admin_preview` and `admin_apply`.

## MCP tools

The HTTPS MCP endpoint exposes six Admin tools. There is no MCP tool to undo a change, unblock a device, cancel a safeguard or edit a plan; undo and unblock are the operator commands above.

| Tool | Arguments | Current behavior |
|---|---|---|
| admin_doctor | `device` | Readiness report without a change: `ready`, and `checks` whose status is `ok`, `missing`, `refused` or `skipped`; `operations` maps each table of the platform to its operations, or to `not measured on this firmware`, for the firmware read from the device |
| admin_preview | `device`, `table`, `op`, `key`, `changes`, `reason`, `user_request`, `request_id` | Every check of apply without a change: `result` is `ready`, `rejected` with `reasons`, or `known-request` with the `change_id` of an earlier operation of the same `request_id` |
| admin_apply | as admin_preview | One change behind the device safeguard; `result` is `confirmed`, `reverted`, `rejected`, `unknown` or `revert-failed` |
| admin_status | `change_id` or `request_id` | The stored operation record; `unknown-operation` when nothing matches, also for a call with neither argument |
| admin_schema_preview | `device`, `operations`, `reason`, `user_request`, `request_id` | Checks of a schema transaction without a change |
| admin_schema_apply | as admin_schema_preview | A schema transaction behind the device safeguard |

`op` is `create`, `update` or `delete`. `key` has at most 128 characters and `table` at most 64. `changes` maps at most 16 attribute names (a lowercase letter followed by up to 63 lowercase letters, digits or hyphens) to a string, an integer, a list of strings or `null` to remove the attribute; for `delete` it is empty. `reason` has at most 500 characters and `user_request` at most 4000. `request_id` has 8–64 letters, digits, `.`, `_`, `:` or `-`. A schema transaction has 1–32 `operations`, each an object with exactly `path`, `scope`, `owners`, `op` and `changes`; it requires a FortiOS device with a configured operator `schema` binding and is otherwise rejected with `schema transactions require a configured operator binding`. A binding names its schema library and rollback calibration by absolute file paths inside the container, and NetOps 1.0 has no supported way to place those files, so schema transactions are not a supported workflow in NetOps 1.0.

## Safety and results

Safeguards last 60–900 seconds; the confirmation margin is at least 15 seconds and at most the safeguard interval minus 15 seconds. Protected objects and their references are refused. Existing per-device/hour, daily, rejection, command and journal limits remain enforced. The per-device `legacy_ssh` exception (`rsa-sha1` or `rsa-sha1-dh14`) retains normal host-key pinning.

Rejected operations, unknown outcomes and reverted/failed returns are MCP errors. Structured results, reasons, request/change IDs and device blocks are preserved. A successful status lookup may report a previously failed operation. A `change_id` or `request_id` that matches no operation is a failed lookup, not an operation with an unknown outcome, and says nothing about the device: the MCP tool `admin_status` returns `unknown-operation` with the reason `no operation matches` as an MCP error, and the operator command `admin status` prints `"result": "rejected"` with the same reason and exits with status 3. Both forms mean the same. Never automatically retry unknown writes: inspect the actual device and journal and use explicit recovery.

The mandatory gateway audit records HTTPS MCP requests before dispatch and responses before delivery. Offline Admin operator workflows run while the gateway is stopped. Before each workflow, a short process under the gateway UID durably records an operator-preflight event with an allowlisted workflow name; device aliases, reasons and other argument values are not copied into that event. The Admin engine then records the operation in its private operations.jsonl and change journal. The preflight event records intent to start, not successful completion; inspect the private operation record and actual device state for the outcome.

Missing or invalid gateway audit configuration, an unwritable audit, a failed durable write or a detected incomplete final local record refuses the workflow. Existing complete JSONL records are not revalidated by this preflight, and local audit does not prove freedom from privileged tampering. The diagnostic reports only the exception type. MCP calls are refused before dispatch when their gateway audit cannot be written. Admin checks its private operation log before device writes.

Optional legacy engine export-status files are not provisioned by the product and are absent from the example. No legacy exporter is required in the unified product. A result with no legacy exporter records independent Admin-log delivery as not configured, never acknowledged. If an operator configures a legacy export-status file, unreadable, stale or blocked status still refuses changes. Notifications use trusted HTTPS; redirects and failed TLS verification are refused.
