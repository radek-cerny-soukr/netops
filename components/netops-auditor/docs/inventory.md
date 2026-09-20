# The inventory file

The inventory is the list of devices the family may reach. Since 0.2.0 it is **the shared document of
`netops-core`, file version 2**: the common part of a device - its name, platform, address, role,
credential name, host key pin and legacy SSH exception - is read by `netops_core.inventory` and is
documented in [`../../netops-core/docs/inventory.md`](../../netops-core/docs/inventory.md). This
document ships in the `netops-core` archive, not in the auditor archive: that relative path resolves
in a repository checkout; from a standalone auditor archive the same file is published at
[`netops-core/v0.2.0`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.0/components/netops-core/docs/inventory.md).
That page is the schema of everything this one does not repeat.

What each component needs for itself lives in a section of its own name. The auditor owns the
`auditor` section, and this page is its schema. **A device is the auditor's when its `auditor` field is
an object**; a device whose `auditor` is `null` belongs to another component, and the auditor neither
validates nor reads it.

Both loaders are **fail-closed**. Every field below must be present in every `auditor` section, even
when its value is `null`, an unknown field is an error, and a wrong value is an error - never a
default. Every refusal names the device and the field.

## A document with one device of each channel

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
      "credential": "fw-a-audit-ro",
      "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "legacy_ssh": null,
      "auditor": {
        "channel": "ssh",
        "source": null,
        "required_sections": ["system global", "system interface", "firewall policy"],
        "tls_fingerprint": null
      },
      "helper": null
    },
    {
      "name": "fw-b.example.invalid",
      "platform": "fortios",
      "address": null,
      "port": null,
      "role": "interni",
      "credential": "fw-b-audit-ro",
      "host_key_fingerprint": null,
      "legacy_ssh": null,
      "auditor": {
        "channel": "fortios-rest",
        "source": "https://192.0.2.20",
        "required_sections": ["system global"],
        "tls_fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      "helper": null
    },
    {
      "name": "fw-c.example.invalid",
      "platform": "fortios",
      "address": null,
      "port": null,
      "role": "lab",
      "credential": null,
      "host_key_fingerprint": null,
      "legacy_ssh": null,
      "auditor": {
        "channel": "file",
        "source": "/var/lib/netops/fw-c.conf",
        "required_sections": ["system global"],
        "tls_fingerprint": null
      },
      "helper": null
    }
  ]
}
```

`version` is `2`. A version `1` document - the shape the auditor read until 0.1.0 - is refused, naming
the version found and the one expected:

```
inventory file inventory.json: unknown inventory file version 1, expected 2
```

The old per-device fields `channel`, `source`, `required_sections` and `tls_fingerprint` moved into
the `auditor` section, `consumer` is gone (the section itself says whose the device is), and the
target of the `ssh` channel is now the common `address` and `port`.

## The `auditor` section

| field | value | note |
|---|---|---|
| `channel` | `file`, `fortios-rest`, `ssh` | one channel per device, no fallback - see [`channels.md`](channels.md) |
| `source` | text, or `null` | a path for `file`, `https://host[:port]` for `fortios-rest`, and **`null` for `ssh`**, which is reached by the common `address` and `port` |
| `required_sections` | non-empty list of texts | section names the dump must hold, written without the header its platform puts around them - see below |
| `tls_fingerprint` | 64 hex characters, or `null` | only for `fortios-rest`, `null` for the other channels |

## What a channel requires of the common part

The channel decides what the shared fields must hold. Each of these is checked when the inventory is
loaded, and the refusal names the device and the field:

| | `file` | `fortios-rest` | `ssh` |
|---|---|---|---|
| `source` of the section | path to a dump | `https://host[:port]` | `null` |
| `credential` | `null` | required | required |
| `address` / `port` | may be `null` | may be `null` | **required** |
| `host_key_fingerprint` | - | `null` | **required** |
| `tls_fingerprint` of the section | `null` | **required** | `null` |
| `legacy_ssh` | `null` (it needs a host key pin) | `null` (it needs a host key pin) | `null` or a profile |

The two fingerprints are pins: there is no trust on first use anywhere in this tool. Take them with
`ssh-keygen -lf` for a host key and from the certificate for TLS, over a path you trust.

A credential is a **record name**, never a secret. What the record must be per channel is decided when
the credential is resolved, not when the inventory is read: `fortios-rest` takes a credential of kind
`api-token`, `ssh` takes `password` or `ssh-key`, and the login of an `ssh` session is the `login` of
that record. The credential store is in [`configuration.md`](configuration.md).

## `required_sections`: the section name, never the header line

A section is named the way the auditor names it, not the way the dump wraps it. FortiOS opens a
section with `config system global`, so the entry says `system global`. EXOS marks a module with
`# Module vlan configuration.`, so the entry says `vlan`. Which header belongs to which platform is
in [`channels.md`](channels.md).

The name is paired whole - `system` does not match `system interface` - and the indentation of the
line in the dump plays no part.

**A section written as a header line is refused, not returned as missing.** A header never matches
itself, so such an entry would come back as a hole that is not there, and an audit tool that lies
about what is on the device is worse than one that stops:

```
completeness: required section 'config system global' is written the way platform fortios opens a
section in the dump (config <section>); the check needs the section alone, so write 'system global'
instead
```

The refusal comes from the completeness measurement, which runs **after** the snapshot has been
taken, not when the inventory is loaded. A typo here therefore ends a collection that has already
reached the device, and until then the same entry loads without a word.

## `legacy_ssh`: old algorithms are an exception, named per device

The field is part of the common device, so the whole family reads it the same way; the rules and the
options behind a profile name are in
[`../../netops-core/docs/inventory.md`](../../netops-core/docs/inventory.md) and
[`../../netops-core/docs/ssh.md`](../../netops-core/docs/ssh.md). Both relative paths resolve in a
repository checkout; from a standalone auditor archive the same two files are published at
[`netops-core/v0.2.0`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.0/components/netops-core/docs/inventory.md)
and
[`netops-core/v0.2.0`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.0/components/netops-core/docs/ssh.md).
What matters here:

- The `ssh` channel talks with the algorithms a current OpenSSH client offers by default. Some
  switches that are still in service offer only `ssh-rsa` - RSA with SHA-1 - and with that default the
  collection stops before the credential is used.
- **The default does not move.** There is no global option, no environment variable and no command
  line flag; the only way is `"legacy_ssh": "rsa-sha1"` in the entry of the one device that needs it,
  and the field requires a pinned host key.
- The value is a **profile name**, not a list of algorithms, so no string from the inventory reaches
  the command line of `ssh`.
- **The exception is visible while it is used.** The collection report - text and JSON - carries
  `collection-legacy_ssh` with the profile name, or `none` when the session ran on current
  algorithms.
- When a device needs the exception and does not have it, the failed call says so and names the field,
  the profile list, and that there is no global switch.

## What the inventory refuses

From the common loader: a missing or unknown device field, a duplicate `name`, a `version` other than
`2`, a field whose name looks like a secret (`password`, `token`, `psk`, `private_key` and others), an
address that is not a canonical IPv4 literal or a lowercase DNS name, an IPv6 target, a `platform`
outside the closed list, a `role` outside `perimetr`, `interni`, `lab`, a host key pin that is not
`SHA256:` plus 43 base64 characters, a `legacy_ssh` profile that is not named in the family or has no
host key pin to go with it, and a device that no component consumes.

From the `auditor` section: a missing or unknown section field, a `channel` outside the three, a
`source` on `ssh` or a missing one elsewhere, an empty `required_sections` or an entry in it that is
not a non-empty string, a `tls_fingerprint` that is not 64 hexadecimal characters or one on a channel
that has no use for it, and every cross-check of the table above.
