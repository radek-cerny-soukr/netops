# FortiOS webhook safeguard contract

Status: contract for NetOps 1.0.5. It states what the code must do before the code is written. The full `admin apply` path on FortiOS 8.0.2 build0251 was measured live on 2026-11-02 ([verified support](verified-support.md#admin-safeguard-on-fortios-76-and-80)).

## 1. Why a second mechanism

Every FortiOS Admin write runs behind a one-shot automation stitch installed before the change. On FortiOS 7.6 and 8.0.0 the stitch runs a `cli-script` action that holds the inverse configuration commands. A Fortinet Technical Tip states that from FortiOS 8.0.1 build0185 the auto-script engine allows only information-gathering commands (`get`, `diagnose`). On FortiOS 8.0.2 build0251 (FortiGate 80F) the `cli-script` action of a fired stitch refused every configuration line, while the 8.0.2 Administration Guide still shows CLI script examples with configuration commands. This is an observed refusal on the measured build and the documented statement of the Technical Tip, not a measurement of every 8.0.x build; Admin therefore does not rely on a `cli-script` action to restore configuration from 8.0.1 (see [verified support](verified-support.md)).

Measured on 2026-11-01 on a FortiGate 80F active-passive HA pair with FortiOS 8.0.2 build0251: a one-shot stitch whose action is `webhook` calling the REST API of the same FortiGate removed a new address (`DELETE`), removed a new policy (`DELETE`) and restored a changed policy attribute (`PUT` with `http-body`), each after the administrator session had ended, without traffic loss and with the HA pair in sync. The device logged the change 4 to 5 seconds after `trigger-datetime`. One manual test run returned HTTP 200.

## 2. Mechanism selection

The mechanism follows the firmware of the snapshot; there is no configuration option and nothing extra for the operator to choose:

| Firmware | Mechanism |
|---|---|
| FortiOS 7.6.x, 8.0.0 | `cli-script` (unchanged) |
| FortiOS 8.0.1 and later | `webhook` |

A profile still has to list the exact build; unlisted builds are refused as before. Schema transactions (`admin_schema_apply`) keep their own measured build binding and are not changed; they are not covered by the webhook mechanism.

## 3. Preflight (before any device write)

On webhook firmware Admin refuses the request after profile validation (an unlisted build is refused first, as before) and before installing anything, when any of these fails. Each refusal names the missing condition. The enrollment self-test, every preview and every apply evaluate all of them. `admin doctor` evaluates the conditions that do not depend on a request, 1 to 6, in its check `webhook safeguard`, with the same refusal texts; conditions 7 to 9 depend on the request and are left to preview and apply. The HTTPS admin port is read with `show system global` before any device write; a port that cannot be read refuses the request (*"the HTTPS administration port cannot be read"*):

1. The device `address` in the Admin configuration is an IPv4 literal. *"the webhook safeguard needs the device address as an IPv4 address, not a host name"*
2. An interface in the snapshot carries that address (`set ip ADDRESS MASK`). *"the webhook safeguard calls the device at ADDRESS, but no interface holds that address"*
3. That interface has `https` in `allowaccess`. *"the webhook safeguard needs https in allowaccess of interface NAME"*
4. The HTTPS admin port is read from `system global` `admin-sport` before the API user is created; when the answer omits it, the FortiOS default 443 is used.
5. The write credential is a password credential: `execute api-user generate-key` asks for the current administrator password. *"the webhook safeguard needs a password write credential: FortiOS asks for the administrator password when it generates the API key"*
   On these builds the write account has the access profile `super_admin`, taken from its `system admin` entry in the snapshot: only `super_admin` may create the API user (FortiOS 8.0.2 build0251 answers `config system api-user` from any other profile with `command parse error before 'api-user'`). *"the webhook safeguard needs the write account LOGIN with access profile super_admin on FortiOS 8.0.1 and later (only super_admin may create the API user of the safeguard); LOGIN has access profile NAME"*; when the entry is missing: *"the webhook safeguard cannot find the write account LOGIN in system admin; on FortiOS 8.0.1 and later it needs access profile super_admin"*
6. No `system api-user` or `system accprofile` entry starting with `netops-sg-` exists (left from an earlier operation). *"a safeguard of an earlier operation is still installed: NAME"*
7. The table has a REST inverse (section 5). `system dhcp server/reserved-address` has none in 1.0.5. *"the webhook safeguard has no REST inverse for table TABLE"*
8. The rendered `http-body` is at most 1023 bytes (NetOps limit, the same as the script limit). *"the inverse exceeds the safeguard request body limit"*
9. For a policy delete (only the undo of a NetOps create), the policy is the last policy in the table, because the `POST` inverse appends it at the end. *"the policy is no longer the last policy; recreating it would change the policy order"*. This check applies to both mechanisms, also on FortiOS 7.6.8: the `cli-script` inverse also recreates the policy at the end. It is a visible change for 7.6.8 users: once another policy has been added after the NetOps policy, its undo is refused.

## 4. Sequence

Names use the first 12 characters of the change ID: accprofile `netops-sg-ID12-p`, API user `netops-sg-ID12-u`, action `-a`, trigger `-t`, stitch `-s`.

1. **install**
   1. accprofile `-p`: `fwgrp read-write`; `secfabgrp`, `ftviewgrp`, `authgrp`, `sysgrp`, `netgrp`, `loggrp`, `vpngrp`, `utmgrp`, `wifi` `none`.
   2. API user `-u`: `accprofile -p`, `config trusthost` / `edit 1` / `set type ipv4-trusthost` / `set ipv4-trusthost ADDRESS 255.255.255.255`. No `vdom` line (FortiOS 8.0.2 refuses it). FortiOS 8.0.2 build0251 asks `Please enter current administrator password:` after the `next` that saves the API user and after `delete` of an API user; Admin answers with the write credential, and only when the device asks.
   3. `execute api-user generate-key netops-sg-ID12-u`; Admin answers the password prompt with the write credential and reads the token from the answer.
   4. action `-a`: `action-type webhook`, `protocol https`, `method` (section 5), `uri "ADDRESS/api/v2/cmdb/PATH"`, `port ADMIN-SPORT`, `verify-host-cert disable` (the target is the device itself), `http-body` when needed, `http-headers` entry 1 `key "Authorization"`, `value "Bearer TOKEN"`.
   5. trigger `-t`: `scheduled`, `once`, `trigger-datetime` = device clock + `safeguard_seconds`.
   6. stitch `-s`: `status enable`, the trigger and one action.
2. **verify**: read back all five objects (the action through `show full-configuration system automation-action NAME`). The action must match method, URI, port, body and header name; the header value is compared with the token in memory and never copied into a message. Any difference or read failure removes everything and ends `reverted` with `safeguard not verified` (or `unknown` when the removal cannot be proven), before the change.
3. **apply**: unchanged.
4. **confirm**: unchanged checks, then remove stitch, trigger, action, API user and accprofile in this order and read back that all five are gone.
5. **expire**: unchanged wait until `fire_at` plus 20 seconds, then compare with the before state; then remove all five objects as in confirm.
6. **recover** (`admin recover`): as today, with the API user and accprofile added to the readback and to the removal. Recover deletes the API user and accprofile and proves their absence by readback; until then the token stays valid. Recover also removes what is left of the safeguard of the operation that blocks the device when it ended `unknown` with `safeguard not verified` before `change_start` (a partial installation whose own cleanup was not proven): it deletes the remaining `netops-sg-ID12-…` objects of that change ID, reads them back and appends `safeguard_removed` (or `safeguard_removal_unverified`); the result stays `unknown` and the block stays for `admin unblock`.

### Webhook did not fire or failed

NetOps reads no HTTP status. The result is judged only by reading the object back:

- object back in the before state: `reverted`;
- object still changed: `unknown` with `safeguard_kept`, the device stays blocked as today. On webhook firmware Admin then deletes the API user and accprofile (token revoked, step `safeguard_token_revoked`, or `safeguard_token_revoke_unverified` when the readback does not prove it) and keeps the stitch, trigger and action as the marker for the person who investigates.

## 5. Inverse per operation

One action per stitch; NetOps never relies on the order of several actions.

| Operation | Inverse request | Notes |
|---|---|---|
| create | `DELETE /api/v2/cmdb/TABLE/KEY` | measured for address and policy |
| update | `PUT /api/v2/cmdb/TABLE/KEY`, body with the before value of every changed attribute; an attribute absent before gets its profile default, or `""` without a default | measured for policy `comments` |
| delete (policy: undo of a create only) | `POST /api/v2/cmdb/TABLE`, body with the key field and every before attribute | measured for policy on 8.0.2 build0251 (FortiGate 80F HA, 2026-11-02): the undo of a policy create with the check account lost after `change_applied` ended `reverted` after `trigger-datetime`; the policy gets a new UUID (already declared in `inverse_identity_changes`); position is kept only because preflight 9 requires the policy to be last |

`TABLE` is the table with the space replaced by `/` (`firewall/policy`, `firewall/address`, `firewall/addrgrp`); `KEY` is percent-encoded. Body values: name lists as `[{"name": ...}]`, text as a string, the policy key `policyid` as a number, address and group key `name`.

## 6. Token life cycle

- It exists from `generate-key` until the API user is deleted.
- It lives only in the memory of the running apply call. It is sent to the device only inside the interactive SSH session; it is never in a process argument list, the plan, the preview, the operation record, its steps, the Admin audit log, a notification, an error text or a NetOps log.
- Firing the webhook does not revoke the token. It is revoked only by deleting the API user: at confirm, after expiry, on failed installation, in the firing-not-proven case (section 4) and in recover.
- When NetOps stops during the window, the device may keep up to five objects. The trigger still fires once at `fire_at`; the token stays valid until `admin recover` or a person deletes the API user. Manual cleanup:

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

## 7. Residual risk (text for the documentation)

> On FortiOS 8.0.1 and later the Admin safeguard calls the REST API of the device itself with a temporary API token. FortiOS keeps the `Authorization` header of the automation action in clear text in the configuration while the safeguard exists, so configuration backups taken during the window hold it. FortiOS also writes the header into the event log when the action is created (log ID 0100044547); the token therefore reaches syslog and FortiAnalyzer when logs are forwarded. Deleting the action does not remove it from those logs; NetOps neither disables logging nor deletes logs. The token is limited: it is accepted only from the device's own management address (trusthost /32), it carries `fwgrp read-write` and nothing else, and it is revoked when NetOps deletes the API user after confirmation, after expiry or in `admin recover`. `fwgrp read-write` is the whole firewall permission group, not one policy: whoever holds the token on the device itself can change any firewall object until it is revoked. If NetOps stops during the window, the token stays valid until `admin recover` or a manual cleanup. Helper `config_read` hides the header value.

## 8. Account requirements

On 8.0.1 and later the write account must have the access profile `super_admin` (preflight 5), because only `super_admin` may create the API user; see the [account model](account-model.md). The write credential must be a password credential (preflight 5).

## 9. Profiles, changelog, documentation

- `firewall policy`: `versions` adds `8.0.2 build0251`; `provisional` is `true`: create and undo of a policy were measured on 7.6.8 build3744 and 8.0.2 build0251, the cleanup was verified, but the run with the whole management path blocked on 8.0.2 was not repeated; `rollback_evidence` names the webhook probe and these measurements.
- `firewall address`: `versions` adds `8.0.2 build0251`, because `admin enroll --probe` creates an address and enrollment is required before any policy change. The evidence names the measured webhook `DELETE` of an address; update and delete on 8.0.2 are not measured.
- `firewall addrgrp` and `system dhcp server/reserved-address`: unchanged.
- `CHANGELOG.md` 1.0.5: one entry under Added (webhook safeguard on FortiOS 8.0.1+, preflight, token life cycle) and one under Changed (policy undo by delete requires the policy to be last).
- Documentation: [verified support](verified-support.md) safeguard section and table, [Admin configuration](admin-configuration.md) (preflight, residual risk text of section 7, manual cleanup), [account model](account-model.md) (section 8).

## 10. Tests required (RED before code)

- webhook firmware renders the five objects, never `cli-script`; 7.6.8 still renders `cli-script` unchanged;
- create, update and undo by delete are confirmed and leave no `netops-sg-` object; firing reverts each one;
- the token is absent from the audit log, the stored record, the plan, the preview and every refusal text, and Helper `config_read` of the rendered action hides it;
- each preflight condition refuses before any device write, among them a missing `https` in `allowaccess`;
- recover after an interrupted apply deletes the API user and accprofile and proves it by readback;
- the readback accepts only a `scheduled` trigger that fires once at the planned time;
- `admin doctor` reports conditions 1 to 6 and the port in its check `webhook safeguard`, without a device write;
- the Auditor reports every object named `netops-sg-` in the five safeguard sections (`fortios.mgmt.netops-safeguard-leftover`, remediation `admin recover`); Admin ignores only the safeguard of the running operation in its audit after the change;
- firing not proven ends `unknown` with the token revoked and the stitch kept;
- policy undo by delete is refused when the policy is no longer last.
