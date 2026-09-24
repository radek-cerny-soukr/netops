# Planning: rules, limits and what is not known

## Request

One request names one object change: `table`, `op` (`create`, `update`, `delete`), `key`, `changes`, `reason`, `user_request`, `request_id`, optional `device`. Unknown or missing fields are refused. `changes` maps an attribute to a string, an integer, a bounded list of object names or `null`; `null` removes a value where the profile allows it, an omitted attribute is left unchanged. Limits: 16 KiB per request, 16 attributes, key 128 characters, reason 500, user request 4000, `request_id` 8-64 characters of `A-Z a-z 0-9 . _ : -`.

The plan never copies `reason` or `user_request`; it records their length and a SHA-256 of the whole request. Free text can hold secrets, and a hash of a short secret does not protect it from guessing, so the plan is not a place to keep it either.

## Refusal rules

A request is refused before any plan exists when:

- no profile exists for the platform and table, or the snapshot firmware is outside the permitted measured family/build; execution additionally requires enrollment of the actual device/build;
- the operation is not enabled, the key does not match the profile pattern, or the object is protected (profile list plus an optional policy file `{"protected": {"<table>": ["name"]}}`);
- the key differs from an existing object only in letter case;
- `create`: the name appears anywhere in the snapshot, a required attribute is missing, or a platform precheck fails (ExtremeXOS: the tag is used by another VLAN or reserved);
- `update` / `delete`: the object does not exist or holds anything the profile does not model (another attribute, a nested block, another object type, a repeated line);
- `update`: an attribute cannot be updated, the change would do nothing, or it changes an attribute that must not change while the object is referenced;
- `delete`: anything else in the snapshot names the object, or the object lacks an attribute its re-creation needs.

References are found by name anywhere in the snapshot, case-insensitively. That is deliberately wider than the real dependency graph: an unrelated value that equals the name also blocks the change.

## Values

- `ipv4-network` accepts `a.b.c.d/len` or `a.b.c.d m.m.m.m` and refuses host bits, because it is not measured how the device stores them.
- `text` accepts printable ASCII without `"` and `\`, up to the profile limit (FortiOS comment 255, ExtremeXOS description 64, both from the vendor CLI reference). FortiOS drops an over-long comment silently, so the limit is enforced here. An empty string is refused; use `null`.
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
- Reserved ExtremeXOS names and internally allocated VLAN IDs are not known from a configuration; the device refuses them.
- A FortiOS snapshot with VDOMs enabled is refused.
- Offline `plan` does not evaluate the configured device audit policy or grant enrollment. The execution path audits the predicted snapshot before writing and the observed snapshot before confirmation.

The group, DHCP and port-membership value types, rendering constraints and examples are described in [0.2.0 operations](operations-020.md). A DHCP object uses the composite server/reservation key; references to numeric reservation IDs are local to that server, not global names.
