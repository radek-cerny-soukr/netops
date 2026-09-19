# Inventory

The inventory is one JSON document listing the devices every component of the family may reach. It is
read by `netops_core.inventory` and is fail-closed: a document that does not match this page is
refused as a whole, and no device from it is used.

`FILE_VERSION = 2`. A document whose `version` is missing or different is refused, naming what was
found and what is expected.

## Document

| Field | Type | Rule |
|---|---|---|
| `version` | integer | must be `2` |
| `devices` | list of objects | may be empty; a duplicate `name` is refused, naming the name |

## Device

`DEVICE_FIELDS = ("name", "platform", "address", "port", "role", "credential", "host_key_fingerprint", "legacy_ssh", "auditor", "helper")`.
An unknown field is refused, naming the device and the field; a missing field is refused the same way.

| Field | Type | Rule |
|---|---|---|
| `name` | string | non-empty, unique in the document; it is the name every other field is reported against |
| `platform` | string | passed through `platforms.normalize`; a canonical name or a known alias, stored canonical. `PLATFORMS = ("fortios", "exos", "linux", "cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos", "juniper_junos", "juniper_junos_els")`, `ALIASES = {"fortinet": "fortios", "extreme_exos": "exos", "extreme_switch_engine": "exos"}` |
| `address` | string or `null` | a canonical IPv4 literal, or a lowercase DNS name (labels `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, no trailing dot, at most 253 characters). An IPv6 literal is refused with a message saying IPv6 targets are not supported |
| `port` | integer or `null` | 1 to 65535; a boolean is refused. `address` and `port` are both `null` or both set |
| `role` | string | one of `ROLES = ("perimetr", "interni", "lab")` |
| `credential` | string or `null` | a record name in the credential store. The inventory never opens the vault and never checks that the record exists |
| `host_key_fingerprint` | string or `null` | a pin in the form `SHA256:` plus 43 base64 characters (`hostkey.checked_pin`); requires `address` to be set |
| `legacy_ssh` | string or `null` | a profile name from `legacy_ssh.PROFILES` (today only `rsa-sha1`); requires `host_key_fingerprint` to be set |
| `auditor` | object or `null` | the section of the auditor; core only requires it to be `null` or an object |
| `helper` | object or `null` | the section of the helper, under the same rule |

`CONSUMERS = ("auditor", "helper")` are the names of the section fields. At least one of the two must
be an object: a device that no component consumes is refused, naming the device.

The content of a section is not validated here. Core carries it as given; the component that owns the
section validates it. This is what lets one inventory serve components with different needs without
core knowing what either of them puts in its section.

## Field names carry no secret

Every field name is checked against the secret markers (`password`, `secret`, `token`, `key`, and
their relatives) before the value is read. A device that names such a field is refused: credentials
live in the vault, and the inventory only names a record.

## Reading it

| Call | Returns | Refusal |
|---|---|---|
| `load(path)` | a tuple of `Device` | the document or any device that breaks a rule above |
| `device(devices, name)` | the `Device` of that name | an unknown name, listing the known names |
| `for_consumer(devices, consumer)` | the devices whose section for that consumer is an object | a consumer outside `CONSUMERS`, naming the allowed ones |

`Device` is a frozen dataclass with the ten fields; `auditor` and `helper` are `dict | None` and hold
what the document held. `Device.consumers()` returns the names of the sections that are not `null`,
in `CONSUMERS` order.

## Example document

```json
{
  "version": 2,
  "devices": [
    {
      "name": "fw-a.example.invalid",
      "platform": "fortios",
      "address": "192.0.2.10",
      "port": 22,
      "role": "perimetr",
      "credential": "fw-a-ro",
      "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "legacy_ssh": null,
      "auditor": {"channel": "ssh", "required_sections": ["system global"]},
      "helper": null
    },
    {
      "name": "sw-a.example.invalid",
      "platform": "exos",
      "address": "192.0.2.20",
      "port": 22,
      "role": "interni",
      "credential": "sw-a-ro",
      "host_key_fingerprint": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "legacy_ssh": "rsa-sha1",
      "auditor": null,
      "helper": {"account_role": "read-only"}
    }
  ]
}
```

The fingerprints above have the shape of a pin and are not real keys. Both addresses are RFC 5737
documentation addresses and both names are in the RFC 2606 reserved domain.

## Legacy SSH is an exception per device

`legacy_ssh` names a profile, never an algorithm list, so no string from the inventory becomes part of
a command line. `PROFILES = ("rsa-sha1",)` expands to `HostKeyAlgorithms=+ssh-rsa` and
`PubkeyAcceptedAlgorithms=+ssh-rsa` for that one device. The profile requires a host key pin: an
exception for a device whose key is not pinned would weaken the algorithms without anything left to
recognise the device by, and it is refused with that reason. There is no global switch.
