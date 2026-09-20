# Collection channels

The auditor reads a device configuration through exactly one channel per device. The channel is
pinned in the inventory (`channel`), together with the fingerprint that channel needs
(`tls_fingerprint` for `fortios-rest`, `host_key_fingerprint` for `ssh`). There is no fallback
ladder: if the chosen channel fails, the collection fails and says why. Choosing a channel is the
operator's decision, so this page describes what each channel does and - more importantly - what it
does not do and what that costs.

Both device channels share the same rules:

- the answer is never logged; a `ChannelEvent` carries the request, the sha256 and the length of
  the raw answer,
- every command sent to a device is one `ChannelEvent`, with the request written down verbatim,
- the credential never appears in the request, in the audit trail, in a `repr` or in an error text,
  and neither does anything the device wrote on standard error: an error names a classified reason,
  never the peer's words,
- the peer is verified before the credential is sent,
- the timeout is mandatory and finite,
- the answer is bounded in bytes as well as in time: `fortios-rest` holds its own budget (see
  below), `ssh` inherits the bounded receive of `netops_core.ssh`, and neither channel grows a
  buffer until the host runs out of memory,
- the transport is injectable, so the test suite never touches the network,
- the auditor never changes a device. Not a policy, not an interface, not even a console setting.

## Two things are called a profile

The word turns up on this page in two unrelated meanings, and mixing them up costs a collection:

| what | where it lives | what it is |
|---|---|---|
| an access profile | on the device, on the account or on the token | how much of the configuration comes back - the auditor neither sets it nor sees it |
| `legacy_ssh` | the common part of the inventory entry | a named set of SSH algorithm options, expanded by the transport - see below |

Neither is the auditor's to set. The third meaning is gone: the option `--profile` of `collect` was
removed; the login of an `ssh` session is now the `login` of the credential the
inventory names. The report says which account was used in `collection-profile` and which kind of
record opened the session in `collection-credential-kind`; on `file` and `fortios-rest`, which log in
as nobody, `collection-profile` is `unknown`.

## Channel `fortios-rest`

### What it does

- Sends `POST https://<host>/api/v2/monitor/system/config/backup?scope=global` and takes the answer
  as the configuration text. The API token travels in the `Authorization: Bearer` header, never in
  the URL: a token in a query string ends up in the device log and in every proxy log on the way.
- Never sends the token to an unverified peer - but the two ways it verifies are not the same
  thing. **Without a pin** the call runs on the default context: the chain is validated against the
  system CA store and the hostname is checked. **With a pin** in the inventory the context is opened
  with `check_hostname = False` and `verify_mode = CERT_NONE`, so the chain is not validated at all;
  the trust rests entirely on the sha256 of the certificate the device presented, which is compared
  against the pin before the request is sent, so a mismatch drops the connection with the token
  unused. A pin is not "TLS plus a fingerprint", it is a fingerprint **instead of** a chain.
  Measured against a local server with a self-signed certificate: without a pin the connection ends
  in `CERTIFICATE_VERIFY_FAILED`, with a pin it is established and the fingerprint decides.
- Default timeout 30 s, and it is **one** deadline: the request, the response headers and every
  block of the body are measured against the same moment, so a peer cannot hold the collection open
  by answering slowly in small pieces. The deadline reaches the socket itself: every receive is
  given only the time that is left, so the budget bounds the **sum** of the waits and not the idle
  time of one read, and an error status is read under the same clock. Measured against a local peer
  that answered one byte every 50 ms on a 0.2 s budget: the call ended after 0.201 s for a slow
  body, a slow error status and slow headers alike.
- **Bounded body, measured before a block is kept.** The answer is assembled block by block, and the
  running total is compared against `--max-response-bytes` of `collect` before each block is added,
  so a body that will not fit is refused while it is still arriving. The default is `8388608`,
  8 MiB - sized for a configuration export rather than copied from the 2 MB cap of `netops-helper`,
  which bounds the output of a command; the largest dump measured on this page is 57,258 lines, and
  even at a generous hundred bytes per line that stays under 6 MB. The refusal names the limit and
  nothing of the peer's words. Why the number is what it is, and how to raise it, is in
  [`configuration.md`](configuration.md).
- **An error status ends the call without a body.** When the HTTP status is not `200` the collector
  reads at most a small head of the answer, throws it away and reports the status alone. An error
  page is never assembled, never hashed and never anywhere near a log, and the channel event of such
  a call therefore records zero bytes - which is exactly what was taken from it.

### What it does not do, and what it costs

- **The export is not byte-stable.** Every PEM envelope of a private key is salted on its own, so
  two exports of an untouched device differ by hundreds of lines (~574 lines measured). A diff of
  findings over an unchanged device is therefore not empty unless those blocks are ignored.
- **The export carries private key material** (22 occurrences of `set private-key` measured), so
  more secrets pass through the tool than an audit needs.
- **The content depends on the access profile of the API user, not on the protocol.** With the
  `api_migration_rw` profile the answer misses the `super_admin` scope (the built-in `admin` account
  is absent). With the `super_admin` profile the same endpoint returned a superset of the CLI dump
  (17,323 lines against 16,115). A weaker profile gives a quietly incomplete picture.
- **The method does not separate reading from writing.** The backup endpoint is a `POST`, and the
  `/api/v2/cmdb/` branch can write. The boundary between read and write is the profile of the token,
  not the HTTP verb.
- Devices usually carry a self-signed certificate, so without a pinned fingerprint in the inventory
  there is nothing to verify the peer against.
- Only the `monitor/.../config/backup` endpoint is used. The `/api/v2/cmdb/` branch, which returns
  the configuration as JSON and would need no parser at all, is not used here.
- FortiOS only. There is no REST channel for any other platform.

### Tested against

**Not verified against a real device with this code.** The numbers above were measured with a
different tool; this collector has never talked to a FortiGate. Treat the REST channel as untested
until someone runs it against a device and writes the result here.

## Channel `ssh`

The transport is `netops_core.ssh`, shared with the rest of the family: the client call,
the hardening options, the workspace and the two kinds of authentication are described in
[`../../netops-core/docs/ssh.md`](../../netops-core/docs/ssh.md) and measured there against real
devices. These documents ship in the `netops-core` archive, not in the auditor archive: that relative
path resolves in a repository checkout; from a standalone auditor archive the same file is published
at [`netops-core/v0.2.2`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.2/components/netops-core/docs/ssh.md).
What the auditor adds is the step table of the platform, the preflight and the `ChannelEvent` of
every command; the prompt cleaning is `netops_core.prompt`. It adds **nothing** to the options of
the client.

### What it does

- Runs OpenSSH as a subprocess (no paramiko, no netmiko), sends the commands of its platform and
  takes the answer of the last one as the configuration text.
- Takes the commands from a table, one entry per platform, not from a chain of conditions:

  | platform | first command | what it is for | second command |
  |---|---|---|---|
  | `fortios` | `get system console` | read-only check, must answer `output ... standard` | `show` |
  | `exos` | *(none)* | no preamble is sent - see below | `show configuration` |

- Cleans the device prompt out of the answer with `netops_core.prompt`, the rule the family
  shares - see below.
- Configures the client from arguments only, never from a system or user configuration file:
  `-F /dev/null`, `BatchMode=yes`, `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`,
  `ClearAllForwardings=yes`, `ProxyCommand=none`, `PermitLocalCommand=no`, `ControlMaster=no`,
  `ControlPath=none`. `ssh` is a binary that can start other processes, so it is kept on a short
  leash. The child gets a minimal environment (`PATH`, `HOME`, `LC_ALL`) with no agent socket.
- Adds the options of a named legacy profile, and only for the device whose inventory entry names
  one - see below.
- Verifies the host key against `host_key_fingerprint` from the inventory: the key is read with
  `ssh-keyscan`, its sha256 fingerprint is computed and compared with the pin, and only the matching
  key is written into a throwaway `known_hosts` that the session then uses with
  `StrictHostKeyChecking=yes`. There is no trust on first use.
- **Authenticates with a key or with a password.** A record of kind `ssh-key` is written into a file
  with mode 0600 in a private temporary directory and passed as `-i <path>`; a record of kind
  `password` is written into a file of the same mode that an askpass script reads, and the client is
  called with `BatchMode=no`, `NumberOfPasswordPrompts=1` and `PubkeyAuthentication=no`, so a wrong
  password is one failure instead of a prompt loop or a silent fallback to a key. Either way the credential never reaches `argv`, where `ps`
  would show it to every user on the machine, and never reaches a value in the environment: only the
  path of the file that holds it does. The directory is removed when the call ends, on every path.
- Default timeout 120 s per command, about fifteen times the slowest dump measured (7.7 s). A
  collection runs at most three commands, so the wall clock is bounded by three timeouts.

### Old algorithms, one device at a time

Switches that are still in service offer a single host key algorithm, `ssh-rsa`, which is RSA with
SHA-1. A current client refuses it and the collection ends before the credential is used:

```
Unable to negotiate with <host> port 22: no matching host key type found. Their offer: ssh-rsa
```

Turning SHA-1 back on for the whole tool to reach those boxes would be the wrong trade in an audit
tool: every other device would silently accept it too. So the weakening is a field of the device
entry in the inventory, `legacy_ssh`, and it is a **named profile**, not a list of algorithms:

| `legacy_ssh` | what the transport adds behind the bound options |
|---|---|
| `null` | nothing, the session stays on current algorithms |
| `"rsa-sha1"` | `-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa` |

The profile name is a key into a table in `netops_core.legacy_ssh`; the options themselves are written
down in that module. No string from the inventory ever reaches `-o`, so an inventory file cannot
smuggle an option into the command line of `ssh`. The field needs a pinned host key, so it cannot be
named for a device the client has nothing to recognise - the inventory is fail-closed and refuses
anything else, including a free-text algorithm list.

The name says what it costs: `rsa-sha1` is SHA-1, for that device, for the host key and for the
public key of the client. It is not a compatibility switch to set on a whole fleet. The full schema
of the entry, and how the exception is written down, is in [`inventory.md`](inventory.md).

The exception is visible in the run that used it: the collection report carries
`collection-legacy_ssh` with the profile name, or `none` when the session ran on current algorithms.
The channel event, which is what the database keeps, does not carry the profile today.

Two details that measurement decided rather than reasoning:

- **The host key scan needs nothing.** `ssh-keyscan` asks for its default key types
  (`rsa`, `ecdsa`, `ed25519`), so it reads an `ssh-rsa` key from those switches and the pin is
  verified the usual way. The profile is therefore not passed to the scan, only to `ssh`.
- **Only the two options above.** With them the negotiation gets past the host key and on to
  authentication; the key exchange picked `diffie-hellman-group16-sha512` and the negotiated cipher
  was the OpenSSH `chacha20-poly1305`, so no legacy key exchange or cipher profile is needed. If a box
  turns up that needs one, it gets its own named profile, measured first.

### When the client fails, it says why - in its own words, not the device's

`ssh` reports a failed negotiation on stderr and exits with 255. An answer of the exit code alone
would leave an operator with `failed with exit code 255` and no way to see that a legacy profile was
missing, so the message names a reason. That reason comes from the closed list in `netops_core.ssh`,
matched against what the client wrote; the raw stderr itself never reaches the message, because
stderr is written by the other side and a device can put a secret - or an instruction addressed to an
agent - into it. A failure whose text matches nothing in the list is reported as one this transport
does not recognize.

The raw text is not thrown away: it stays on the exception as `said`, where an operator-side log can
take it. What leaves the auditor - a `CollectError`, a CLI message, a report - carries the classified
sentence. The answer itself, stdout, is never logged at all.

When the client refused to negotiate and the device has no profile, the message also names the
device and says how the exception is written down - the field, the profile names, and that there is
no global switch. With a profile already named the remedy is not repeated, and it never appears for
a failure that is not a negotiation, such as a rejected credential.

### Why `show` and not `show full-configuration`

The two commands are not the same dump with a different level of detail. Measured on a FortiGate 80F
(FortiOS v8.0.0 build0167):

| | `show` | `show full-configuration` |
|---|---|---|
| lines | 20,521 | 57,258 |
| `config` sections | 2,163 | 2,525 |
| `set private-key` | **0** | **22** |
| `set certificate` | **0** | **14** |

`show full-configuration` writes out the default values as well - that is where the extra 36 thousand
lines come from - but it also writes out **private key material**. Taking it would throw away exactly
the property this channel was chosen for: the smallest possible amount of secrets inside the tool.
`show` has neither the defaults nor the keys, and it is the shape the current rules are tuned on.
So the auditor asks for `show`.

### The pager, and why it is not one universal command

FortiOS pages long output over this channel, and EXOS does not, which is where the two platforms
differ in a way the tool has to respect:

- **FortiOS**: turning the pager off means `config system console` / `set output standard`, which is
  **a write into the device configuration**. The auditor must not do that, so it only asks
  `get system console` and reads `output`. Anything other than `standard` and the collection is
  refused with a message that says what to set. The auditor would rather not run than change a
  device for its own convenience.
- **EXOS**: over a non-interactive exec channel the switch does not page at all - measured on
  19 September 2026 against ExtremeXOS 33.7.1: `show configuration` returned 10,728 bytes with zero
  `--More--` markers and a complete final module, and the byte count was identical across three
  shapes - with no preamble, in a fresh session after `disable cli paging` had been sent in a
  separate session, and with both commands sent in one session. `disable cli paging` used to be sent
  as its own step before the snapshot, on the reasoning that it was at worst a harmless property of
  the session rather than of the configuration (verified on the switch, where
  `show configuration | include "paging"` returned nothing after it was sent). The measurement above
  shows it was also unnecessary: the switch never paged over this channel regardless. The auditor
  sends nothing for EXOS now.

One universal "turn the pager off" command would still have to be a write on FortiOS, which is why
FortiOS keeps its own preflight command; EXOS needs no command at all.

### A one-shot command needs no PTY

FortiOS answers a command passed to `ssh` as a remote command, with no terminal allocated. Verified
with the native client and key authentication against FortiOS v8.0.0 build0167:

- `ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=... -o
  IdentitiesOnly=yes -i <key> <login>@<device> "get system status | grep Version"` - exit 0, 0.9 s,
  correct output, no PTY.
- the same invocation with `show full-configuration` - exit 0, 7.7 s, 57,258 lines, `config` 2,525 =
  `end` 2,525, so the dump is complete.

No `--More--` appears anywhere in the output (the only occurrence of the string "More" is the name of
an IPS signature, `Automationdirect.C-More`), and no CRLF comes from the session - the two lines that
carry `\r` hold a multi-line value from inside the configuration itself. The byte stream stays clean,
which is what the stability of this channel rests on, so this collector allocates no PTY (`-tt` is
not among the bound options).

What does need a PTY is the `ssh-manager` wrapper used elsewhere in this homelab, because it wraps
the command in `timeout N sh -c '...'`. That is a property of the wrapper, not of FortiOS.

### The prompt in the output, and the two hashes

A FortiOS device answers a one-shot command with its prompt printed into the output. Measured on the
FortiGate 80F, `cat -A`, `$` marks the end of a line:

```
FortiGate-80F # output              : standard $
login               : enable $
fortiexplorer       : enable $
$
FortiGate-80F #
```

The prompt is **glued to the first line** and hangs at the end as a line of its own. The
configuration dump has it too:

```
first line:   FortiGate-80F # #config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=...
last line:    FortiGate-80F #
```

Left alone, this breaks two things: the preflight never finds its field (the key on the first line
reads `FortiGate-80F # output`, not `output`), and the snapshot carries the hostname of the device
and a prompt instead of being only the configuration.

**The marker depends on the account.** Measured on 17 September 2026 against FortiOS 8.0.0 on the
exec channel: the `super_admin` account answers with `<hostname> # `, and an account with a read-only
profile answers with `<hostname> $ `. Until this release the cleaner knew `#` alone, so under a
read-only account the prompt stayed in the snapshot - and in its hash.

So the answer is cleaned by [`netops_core.prompt`](../../netops-core/docs/prompt.md) (published, for
a standalone archive, at
[`netops-core/v0.2.2`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.2/components/netops-core/docs/prompt.md)),
which the helper uses as well, by a rule that is deliberately narrow:

- **only the first line** can lose a prefix, and only when that line starts with a prompt shape: at
  least one character that is neither `#` nor `$`, a space, then `#` or `$` and a space. A first line
  that begins with `#` - such as `#config-version=...` - is therefore never touched.
- **only trailing lines** can be dropped, and only when they are exactly the same prompt that was
  found on the first line. If the first line carried no prompt, nothing is dropped at the end.
- **the middle is never touched at all.** A `#` inside a value (`edit "net # 42"`, a comment line,
  even `set alias "FortiGate-80F #"`) survives byte for byte, because the cleaner never looks there.

That is why the rule is anchored on the prompt found at the beginning rather than on "a hash
somewhere": a configuration line that happens to contain `#` must not be at risk, and here it cannot
be by construction.

**Two hashes, on purpose.** `ChannelEvent.response_sha256` and `response_bytes` describe the **raw
answer** - what really came back over the channel, prompt and all. That is the trace of the channel
and it has to stay honest. `Snapshot.sha256` and `size_bytes` describe the **cleaned text**, which is
what the auditor evaluates and stores. So **the hash of a snapshot is not the hash of the raw
answer**, and on a device that prints a prompt the two differ. If you compare a snapshot hash against
a dump you took by hand, compare it against the cleaned text, not against the raw session output.
When the device prints no prompt the cleaner does nothing and both hashes are equal.

### What it does not do, and what it costs

- **The configuration of a FortiGate cannot be restored from it.** `show` carries no certificate and
  no private key material (0 occurrences of either, see the table above). That is an advantage for
  an audit and a disqualification for a backup.
- **The content depends on the profile of the account that logs in.** A weaker profile returns a
  quietly incomplete view, and the counts of `config` and `end` still match, so nothing looks wrong.
  Measured on 17 September 2026 against FortiOS 8.0.0: an account bound to a read-only access
  profile (every group `read`, `cli-show enable`) collects the full `show` with the same 2,165
  top-level sections as a `super_admin` account, but `system admin`, `system api-user` and
  `system accprofile` list **only the account's own entries** and `system automation-action` is
  shorter, 20,493 lines against 20,574. Nothing in the answer says so. **The auditor account on
  FortiOS is therefore a `super_admin` administrator** (decision of 17 September 2026): it is the
  only profile whose `show` carries every administrator, API user and access profile, and rules
  over `system admin` need exactly those. The auditor then holds an account that could write; the
  read-only boundary is the step table above (`get system console`, `show`), the pinned host key
  and the absence of any other command in this channel - not the profile. Restrict the account
  with `trusthost` to the collector and log its sessions on the device.
- **An EXOS snapshot is audited by four rules.** The catalogue `exos.json` exists, `run --platform exos` and `collect` over an `exos` entry both
  work, and what those four rules do and do not see is [below](#what-the-exos-catalogue-reads).
- **Unverified:** the behaviour when FortiOS reports `output: more`. Switching a production device
  to the pager would have been a write, so the refusal path was proven in tests, not on a device.
- **An EXOS switch prints no prompt into a one-shot answer.** Measured on 17 September 2026 on the
  exec channel: 0 occurrences in the dump. The same cleaning stays declared for `exos` in the step
  table - it is a no-op there, and it keeps one path for both platforms.

### What it gives you for free

The configuration of a FortiSwitch and of a FortiAP managed over FortiLink is part of the FortiGate
configuration (29 `edit` entries under `switch-controller managed-switch` and one
`wireless-controller wtp` on the lab 60F). One dump therefore covers the whole Fabric, and the
auditor does not have to visit the switch and the access point separately.

A pipe works: `show full-configuration | grep -c "^config"` walks the whole output, so long output
can be processed on the device side.

### Why OpenSSH as a subprocess and not a library

`paramiko` does not connect to the Extreme switches in this fleet at all: it ends with
`IncompatiblePeer` because of the old host key algorithm they offer, while the system `ssh` connects
without a complaint. That is a real case from production, not a preference. The system client also
brings its own host key handling, its own algorithm negotiation and its own maintenance, and the
auditor binds it with arguments instead of trusting a configuration file.

### Tested against

All measurements are from 12 September 2026 and were read-only; nothing was changed on any device.

| device | software | pager preflight | configuration dump | note |
|---|---|---|---|---|
| FortiGate 60F | FortiOS v8.0.0 build0167 (GA.F) | `get system console` -> `output: standard` | `show full-configuration` - 2,421 sections, 3.9 s | FortiSwitch behind it (29 x `edit` in `switch-controller managed-switch`) and a FortiAP (1 x `wireless-controller wtp`) |
| FortiGate 80F | FortiOS v8.0.0 build0167 (GA.F) | `output: standard` | `show` - 20,521 lines, 2,163 sections, no keys; `show full-configuration` - 57,258 lines, 2,525 sections, 6.6 s | no Fabric |
| Extreme X440-G2-12p (two units) | ExtremeXOS 33.7.1.6 | `disable cli paging` | `show configuration` - 1.7 s and 2.3 s | both offer only `ssh-rsa`, both need `legacy_ssh: "rsa-sha1"` |

Beyond the interactive sessions, the channel was also verified as a **one-shot run against the
FortiGate 80F**: a command handed to `ssh` with no PTY, key authentication, full dump in 7.7 s, with
`config` and `end` counts matching and clean output (no pager marker, no CRLF from the session).
That run is also where the prompt in the output was found - the first `collect` against real
hardware failed on it, which no mock would have shown.

On FortiOS two dumps in a row were byte identical, and nine days apart, with dozens of changes in
between, every `ENC` field still matched.

That table is the anchor: if the channel does not work for you, this is the hardware and the firmware
where the behaviour was observed. The measurements above were taken with the historical collector of 0.1.0
(its release, tag and artifact downloads have since been removed), which
carried its own copy of the transport; the current transport is `netops_core.ssh`, measured on the
same devices - including the password authentication this channel had not had before - in
[`../../netops-core/docs/ssh.md`](../../netops-core/docs/ssh.md). The FortiOS commands and preflight
above are the auditor's and did not change. The EXOS preflight shown in that table, `disable cli
paging`, did: the measurement described
[above](#the-pager-and-why-it-is-not-one-universal-command) found it unnecessary, and the current
auditor sends nothing before `show configuration` on EXOS. The prompt cleaning moved to
[`../../netops-core/docs/prompt.md`](../../netops-core/docs/prompt.md) unchanged except for the `$`
marker. Both relative paths resolve in a repository checkout; from a standalone auditor archive the
same two files are published at
[`netops-core/v0.2.2`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.2/components/netops-core/docs/ssh.md)
and
[`netops-core/v0.2.2`](https://github.com/radek-cerny-soukr/netops/blob/netops-core/v0.2.2/components/netops-core/docs/prompt.md).

## Channel `file`

Reads a configuration snapshot from a local file. No credential, no fingerprint, no network. It is
the channel for a dump that somebody else collected, and the only channel that says nothing about
the device being reachable or about the moment the configuration was true.

## What "a complete view" means, per platform

`required_sections` of an inventory entry says which sections a snapshot must hold, and `collect`
measures it once the snapshot is taken. A section is recognized by the header its platform writes
around it, and the platform of the entry decides which header that is - nothing is guessed from the
text of the dump:

| platform | how a dump opens a section | measured on |
|---|---|---|
| `fortios` | `config <section>` | FortiOS v8.0.0 build0167, the `show` dump measured in [Tested against](#tested-against) |
| `exos` | `# Module <section> configuration.` | ExtremeXOS 33.7.1.6, `show configuration` - 49 module headers, the same set on both units |

The two are not one shape with a different keyword. An EXOS configuration is a flat list of commands
- `create ...`, `configure ...`, `enable ...` - not a tree of `config` and `end`; what divides it into
modules is a single comment header per module. A check that looked for `config ` in every dump
therefore found nothing on EXOS, because no EXOS line begins with it (`configure ` is a different
word), and every section such an entry asked for came back missing. Measured again with the header of
the platform: 49 of 49 present.

A missing section is one finding, `<platform>.snapshot.incomplete`, class `fakt`, severity high. It
carries the names and the count, and nothing else - never a line of configuration. It is a presence
check: an empty section counts as present, because the question is whether the dump reaches that far,
not what stands inside.

## What the EXOS catalogue reads

**EXOS has an audit rule catalogue.** The four rules of `exos.json` are
all class `fakt`, and all of them read the flat list of commands the L1 parser builds out of
`show configuration` - a record per command carrying its line, the module declared above it and its
tokens. There is no normalized model between the rules and the text; a rule asks whether a command is
there and what stands in the positions the vendor documentation gives that command.

| rule | severity | what silences it |
|---|---|---|
| `exos.time.no-sntp-client` | medium | `enable sntp-client`, `enable ntp`, or a `configure sntp-client primary` or `configure ntp server add` entry carrying a host |
| `exos.logging.no-syslog-target` | medium | a `configure syslog add` entry carrying a target |
| `exos.snmp.default-community` | high | no community entry whose plainly written index, name or string is in the dictionary `public`, `private` |
| `exos.mgmt.telnet-enabled` | medium | `disable telnet`, as the last of the Telnet commands in the dump |

Every rule cites the commands it rests on in its `refs` - document, chapter and command entry of the
*ExtremeXOS v33.7.1 Command References*, the release running on the switches this catalogue was
written for. `rule_detail` over MCP and `known_false_positives` in the catalogue carry the limits of
each rule; three of them are worth repeating here, because they are properties of EXOS rather than of
the rule:

- **`enable syslog` does not appear in `show configuration`.** Remote logging in 33.7.1 needs both a
  target and that command, whose entry reads `Default: Disabled` - but only the targets are in the
  dump, so the rule rests on the targets alone. A switch with a target that never enabled the export
  is therefore silent.
- **Telnet is enabled by default** (both the `enable telnet` and the `disable telnet` entry read
  `Default: Enabled`), so the absence of any Telnet command is a finding, not silence. A dump that
  was truncated before the `telnetd` module is reported the same way, which is the fail-closed side
  of that choice.
- **The SNTP client and the NTP client are two features, and the time rule reads both.** Version 1 of
  the rule read the SNTP client alone and reported a switch that holds its clock over `enable ntp`
  and `configure ntp server add` - the one false positive seen over a real dump. Version 2 accepts
  either client: the rule asks whether the switch synchronizes from some server, not which of the two
  features it uses. It still does not judge whether that server is the right one, or reachable.

A community string never reaches a finding. The evidence of `exos.snmp.default-community` says which
field of the entry matched - `community index`, `community name` or `community string` - the fixed
first four words of the command, and that the value is in the dictionary. The value itself is not in
the evidence, not in the object key and not in the report; an entry written with the `hex` or the
`encrypted` keyword is not compared at all, because the rule reads plain values only.

### Tested against

Over a real `show configuration` of two switches running ExtremeXOS 33.7.1.6, read from a backup and
never sent to a device: one switch produced **no finding**, the second produced **one**,
`exos.time.no-sntp-client`. That was version 1 of the rule and the finding was the known false
positive above - that switch synchronizes over the NTP client. Version 2 accepts the NTP client, so
the same dump would produce no finding; that has not been measured again over the dump itself, only
over a fixture carrying the same two commands. Four defects inserted into a copy of the first dump - the SNTP server removed, the
syslog target removed, a `public` community added, `disable telnet` removed - each produced **exactly
one** new finding, and two runs over the same dump produced a byte identical report.

**Not measured against a device with this code.** Those dumps were taken by a backup job, not by this
collector; the `ssh` channel has never pulled an EXOS configuration and handed it to this catalogue in
one run.

## Choosing a channel

- `fortios-rest` if you want the configuration in a machine-readable shape from the API, you accept
  that two exports of an untouched device differ, and you accept that private key material passes
  through the tool. Pin the certificate fingerprint, and remember that the completeness of the
  answer is decided by the profile of the token.
- `ssh` if you want a stable diff over an unchanged device and the smallest possible amount of
  secrets inside the tool, and you can live with a console that has to be set to standard output
  and with a dump that cannot restore the device. Pin the host key fingerprint. It is also the only
  channel that speaks EXOS at all.
  On FortiOS enrol a `super_admin` account (see above); on EXOS enrol an administrator account,
  because a user-level account is refused `show configuration` (`This user does not have
  permissions for this command.`, measured 17 September 2026 on ExtremeXOS 33.7.1).
- `file` if the collection happens somewhere else entirely.

Neither remote channel is a fallback for the other. Pick one per device and pin it.
