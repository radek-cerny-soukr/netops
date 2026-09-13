# The inventory file

The inventory is the list of devices the auditor is allowed to read, and the only place where a
device says how it is reached. It is a JSON file you write by hand. It holds no secret: a credential
is named here, its value lives in the credential store, whose schema is in
[`configuration.md`](configuration.md).

The loader is **fail-closed**. Every field listed below must be present in every entry, even when its
value is `null`, an unknown field is an error, and a wrong value is an error - never a default. A
typo therefore stops the run instead of quietly auditing the wrong thing. This page is the schema, so
you do not have to read `inventory.py` to write the file.

## Shape

```json
{
  "version": 1,
  "devices": [
    {
      "name": "fw-a.example.invalid",
      "platform": "fortios",
      "channel": "ssh",
      "source": "192.0.2.10",
      "role": "perimetr",
      "consumer": "auditor",
      "credential": "fw-a-audit-ro",
      "required_sections": ["system global", "system interface", "firewall policy"],
      "tls_fingerprint": null,
      "host_key_fingerprint": "SHA256:replaceMeWithTheRealHostKeyFingerprint12345",
      "legacy_ssh": null
    }
  ]
}
```

`version` is `1`. `devices` is a list; two entries may not share a `name`.

## Fields

| field | value | note |
|---|---|---|
| `name` | non-empty text | how the device is called in reports, the store and on the command line |
| `platform` | `fortios`, `exos` | `exos` collects a snapshot; there are no EXOS rules yet |
| `channel` | `file`, `fortios-rest`, `ssh` | one channel per device, no fallback - see [`channels.md`](channels.md) |
| `source` | non-empty text | a path for `file`, `https://host[:port]` for `fortios-rest`, `host[:port]` for `ssh` |
| `role` | `perimetr`, `interni`, `lab` | what the device guards; rules may be scoped by it |
| `consumer` | `auditor`, `helper` | which tool of the family owns the entry |
| `credential` | record name, or `null` | `null` only for `file`; never a password, never a key |
| `required_sections` | non-empty list of texts | section names the dump must hold, written without the header its platform puts around them - see below |
| `tls_fingerprint` | 64 hex characters, or `null` | only for `fortios-rest`, `null` for the other channels |
| `host_key_fingerprint` | `SHA256:` + 43 base64 characters, or `null` | only for `ssh`, `null` for the other channels |
| `legacy_ssh` | `null` or a profile name | only for `ssh`, `null` for the other channels - see below |

The two fingerprints are pins: there is no trust on first use anywhere in this tool. Take them with
`ssh-keygen -lf` for a host key and from the certificate for TLS, over a path you trust.

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

The `ssh` channel talks to devices with the algorithms a current OpenSSH client offers by default,
and nothing else. Some switches that are still in service offer only `ssh-rsa` - RSA with SHA-1 -
and with the default set the collection stops before the credential is used:

```
Unable to negotiate with <host> port 22: no matching host key type found. Their offer: ssh-rsa
```

**That default does not move.** An audit tool that quietly accepts SHA-1 everywhere in order to reach
one switch has audited nothing. There is no global option, no environment variable and no command
line flag that turns old algorithms on: the only way is to write the exception into the entry of the
one device that needs it.

| `legacy_ssh` | what the session gets | what it means |
|---|---|---|
| `null` | nothing | current algorithms only - the value for every device that does not need the exception |
| `"rsa-sha1"` | `-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa` | SHA-1 is accepted for the host key and for the client public key, **for this device only** |

Both options are written with `+`, which appends to the default set instead of replacing it, so the
old algorithm sits last in the preference list and is chosen only when the device offers nothing
better. Measured against the switches in the table of [`channels.md`](channels.md): the host key half
is what makes the session possible at all, while the client public key half was never the deciding
option there - those devices accept `rsa-sha2-*` signatures. It stays in the profile for a device
that refuses them too, and it costs nothing where it is not needed.

The value is a **profile name**, not a list of algorithms. The options behind a name are written down
in the collector and cannot be extended from the inventory, so a file cannot smuggle an option onto
the command line of `ssh`. An unknown name, an algorithm list, or a name with different spelling is
refused when the inventory is loaded:

```
device 0: legacy_ssh must be null for a device that speaks current algorithms or name one of the
profiles rsa-sha1 for channel ssh, a profile weakens the session for that device alone, got 'ssh-rsa'
```

For the `file` and `fortios-rest` channels the field must be `null`; anything else is an error, so a
profile cannot be left behind when a device moves to another channel.

**The exception is visible while it is used.** The collection report - text and JSON - carries
`collection-legacy_ssh`, with the profile name, or `none` when the session ran on current algorithms.
A report from a device with an exception therefore says so on its face.

**When a device needs the exception and does not have it**, the failure now says so:

```
audit-ro@<host> disable cli paging failed with exit code 255, the client said: Unable to negotiate
with <host> port 22: no matching host key type found. Their offer: ssh-rsa; <host> offers only
algorithms this client refuses - if that is intended for this one device, name the exception in its
inventory entry as legacy_ssh, one of the profiles rsa-sha1; there is no global switch and no other
entry is weakened by it
```

New profiles are added only when a measurement shows a device that cannot be reached without one -
not in advance. The name of a profile says what it costs; `rsa-sha1` says SHA-1.

## Per channel, at a glance

| | `file` | `fortios-rest` | `ssh` |
|---|---|---|---|
| `source` | path to a dump | `https://host[:port]` | `host[:port]` |
| `credential` | `null` | record name | record name |
| `tls_fingerprint` | `null` | required | `null` |
| `host_key_fingerprint` | `null` | `null` | required |
| `legacy_ssh` | `null` | `null` | `null` or a profile |

## What the inventory refuses

- a missing field, an unknown field, a duplicate `name`, a `version` other than `1`,
- a field whose name looks like a secret (`password`, `token`, `psk`, `private_key` and others):
  the check runs before anything else, and it looks at names, not at values,
- a pin, a credential or a profile on a channel that has no use for it,
- a value outside the allowed set for `platform`, `channel`, `role`, `consumer` and `legacy_ssh`.

Every refusal names the entry by its index and says what was found.
