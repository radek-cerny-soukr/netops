# Planning: rules, limits and what is not known

## Request

One request names one object change: `table`, `op` (`create`, `update`, `delete`), `key`, `changes`, `reason`, `user_request`, `request_id`, optional `device`. Unknown or missing fields are refused. `netops-admin apply` and `netops-admin preview` refuse a request whose `device` names another device than `--device`, before the device is contacted; a request without `device` runs on the device of `--device`. The MCP tools take `device` once and use it for both, and `undo` copies the device of the operation it undoes. `changes` maps an attribute to a string, an integer, a bounded list of object names or `null`; `null` removes a value where the profile allows it, an omitted attribute is left unchanged. Limits: 16 KiB per request, 16 attributes, key 128 characters, reason 500, user request 4000, `request_id` 8-64 characters of `A-Z a-z 0-9 . _ : -`.

The plan never copies `reason` or `user_request`; it records their length and a SHA-256 of the whole request. Free text can hold secrets, and a hash of a short secret does not protect it from guessing, so the plan is not a place to keep it either.

## Refusal rules

A request is refused before any plan exists when:

- no profile exists for the platform and table, or the snapshot firmware is outside the permitted measured family/build; execution additionally requires enrollment of the actual device/build;
- the operation is not enabled, the key does not match the profile pattern, or the object is protected (profile list plus an optional policy file `{"protected": {"<table>": ["name"]}}`);
- the object refers to a name under `protected` before or after the change, whatever the change is (create, update or delete, another member of the group, a description). References are read per table: every `name-list` attribute of a profile (`member` of an address group, `tagged` of a port) and the native VLAN of a port (`untagged`); on ExtremeXOS a port refers to every VLAN it is tagged or untagged in, so the display string of such a port (`ports`) is refused, and a VLAN refers to every port it holds (`vlan`). The VLAN membership comes from the snapshot, with the implicit `Default` of the listed ports; when a name is protected and that membership cannot be evaluated, a change of a port or of a VLAN is refused. The other profiles name no other object: a firewall address (`subnet`, `comment`) and a DHCP reservation (`ip`, `mac`, `description`; the server ID in its key names the entry that holds the reservation, not a reference). A name listed under any table counts, compared without letter case. The built-in protected names of the profiles (`all`, `none`, `Default`, `Mgmt`) count only when they are listed: they are refused as keys anyway, and every port of a factory switch without another native VLAN is untagged in `Default`, so counting `Default` would refuse every port change of such a switch and the native move back to it;
- the key differs from an existing object only in letter case;
- `create`: the name is already an object name or a reference in the snapshot (see [Names and references](#names-and-references)), a required attribute is missing, or a platform precheck fails (ExtremeXOS: the tag is used by another VLAN or reserved);
- `update` / `delete`: the object does not exist or holds anything the profile does not model (another attribute, a nested block, another object type, a repeated line);
- `update`: an attribute cannot be updated, the change would do nothing, or it changes an attribute that must not change while the object is referenced;
- `delete`: anything else in the snapshot refers to the object, found the same way, or the object lacks an attribute its re-creation needs.

## Names and references

References are found by name, case-insensitively, in every value that can hold the name of an object, not only in the attributes the profiles model. That is deliberately wider than the real dependency graph: the planner does not know every FortiOS attribute or ExtremeXOS command that names an object, and a reference it missed would let `create` give its name to a new object, which an existing or dangling reference then resolves to, and let `delete` remove an object still in use. An unrelated value that equals the name also blocks the change.

Values that cannot name an object are left out, so that the check does not answer whether a guessed key equals a secret or a free text:

- FortiOS: every entry name of every table counts, and every value of every attribute, except the attributes whose name contains `password`, `passwd`, `passphrase`, `pwd`, `secret`, `psk`, `key`, `community`, `token`, `comment` or `description` (for example `psksecret`, `auth-pwd`, `private-key`, `comments`) and `name` of `system snmp community`, which holds the community string.
- ExtremeXOS: every word of every command counts, except whole commands whose second word is `snmp` or `snmpv3` (communities, SNMPv3 users and the system name, contact and location), the word right after `community`, `encrypted`, `password` or `shared-secret` (so `create account … encrypted "<hash>"` and a RADIUS or TACACS `shared-secret` leave out the secret, while a VLAN named later in the same command still counts), and the words after `description`, `description-string`, `display-string`, `sysName`, `sysContact` or `sysLocation`. Keywords are compared without letter case. A key that equals one of these keywords is compared with every word, as before, so that a VLAN named `description` keeps its references.

A secret in an attribute or a command outside these lists still counts as a name and refuses the request like any other match. A refusal says only that the name is used (`name '<key>' is already used in the configuration`) or that the object is referenced (`object '<key>' is referenced in the configuration`), never where; a refused `preview` counts against `rejections_per_hour` like a refused `apply` (see [execution](execution.md#limits)).

## Values

- `ipv4-network` accepts `a.b.c.d/len` or `a.b.c.d m.m.m.m` and refuses host bits, because it is not measured how the device stores them.
- `text` accepts printable ASCII up to the profile limit (FortiOS comment 255, ExtremeXOS description 64, both from the vendor CLI reference). On FortiOS it may contain `"` and `\`, which the renderer writes escaped inside the quoted value; on ExtremeXOS both are refused, because its CLI has no escape for them. A control character is refused on both. FortiOS drops an over-long comment silently, so the limit is enforced here. An empty string is refused; use `null`.
- `integer` is range-checked; ExtremeXOS tags run from 2 to 4095 (vendor CLI reference); 4095 is refused because the management VLAN held it on the measured switch.
- ExtremeXOS `description` cannot be `none`, the keyword that removes a description.

## Rendering

FortiOS: `config <table>` / `edit "<key>"` / `set` or `unset` / `next` / `end`, text values quoted. Delete is `config <table>` / `delete "<key>"` / `end`. The inverse of create is delete, of update the previous values (or `unset` where there was none), of delete the re-creation from the snapshot.

ExtremeXOS: `create vlan <key> tag <n>`, `configure vlan <key> description "<text>"`, `unconfigure vlan <key> description`, `delete vlan <key>`.

## Prediction and verification

The predicted state leaves out volatile attributes (FortiOS `uuid`), fixed attributes that hold their fixed value and values equal to the profile default, because the device omits them from its configuration. `verify` normalises the later snapshot the same way. Besides the object it compares a digest of the rest of the parsed configuration. FortiOS preserves ordering outside known unordered object tables and normalizes only the exact opaque ciphertext fields documented in [operations](operations-020.md#snapshot-comparison-boundary). EXOS compares other port memberships semantically and the remaining configuration lines. Only the current operation's safeguard is excluded.

The FortiOS inverse of delete recreates the object under a new `uuid`; the plan lists it in `inverse_identity_changes`. Name, attributes and references by name are restored; anything that follows the object by `uuid` sees a new object.

## What planning does not do

- `plan` and `verify` do not collect the snapshot, connect to a device, install a rollback safeguard, apply commands or keep a journal. `apply` does, for FortiOS: [execution.md](execution.md).
- The ExtremeXOS firmware is stated by the caller, not read from the device.
- Offline `plan` does not know the ports of an ExtremeXOS switch. `--ports 1-12` states them as `show ports no-refresh` lists them; the plan then treats a listed port without another native VLAN as untagged in `Default` while the configuration holds no `configure vlan default delete ports all`, and refuses an unlisted port. Without `--ports`, a port without a native VLAN line is refused (`object '<n>' does not exist`) and a display string is planned for any port number the profile pattern allows. `apply` and `preview` read the list from the switch: [execution.md](execution.md#extremexos).
- Reserved ExtremeXOS names and internally allocated VLAN IDs are not known from a configuration; the device refuses them.
- A FortiOS snapshot with VDOMs enabled is refused.
- Offline `plan` does not evaluate the configured device audit policy or grant enrollment. The execution path audits the predicted snapshot before writing and the observed snapshot before confirmation.

The group, DHCP and port-membership value types, rendering constraints and examples are described in [0.2.0 operations](operations-020.md). A DHCP object uses the composite server/reservation key; references to numeric reservation IDs are local to that server, not global names.
