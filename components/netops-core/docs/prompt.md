# Prompt cleaning

`netops_core.prompt` removes the device prompt from a one-shot answer. It is four lines of rule and
one table, and it lives here because both components above the core need exactly the same rule: the
auditor hashes and stores the cleaned text, the helper returns it to a client.

## What a device prints

A device with an exec channel can answer a single command with its own prompt printed into the
output: glued to the front of the first line, and once more at the end as a line of its own.

**Measured on 17 September 2026, FortiOS 8.0.0, one command per connection:**

| account | first line begins with | last line |
|---|---|---|
| `super_admin` profile | `<hostname> # ` | `<hostname> #` |
| read-only profile | `<hostname> $ ` | `<hostname> $` |

The marker is the shell convention: `#` for the privileged account, `$` for the unprivileged one. A
prompt with a virtual domain (`<hostname> (global) # `) is the same shape with a longer name.

**Measured the same day, ExtremeXOS:** the exec channel prints no prompt at all (0 occurrences in the
dump), so cleaning is a no-op there and stays declared only so the two platforms share one path.

## The rule

`cleaned(text, platform)` looks up the platform in the table and, when it finds one:

- matches `^([^#$\n]+ [#$] )` against the **first line only**. A first line that begins with `#` or
  `$` - `#config-version=...`, a comment - can never match, because the first group needs at least
  one character that is neither.
- removes that marker from the first line.
- removes **trailing lines** that are exactly the same marker, stripped. If the first line carried no
  marker, nothing is removed at the end.
- keeps a trailing newline if the answer had one.
- **never touches the middle.** A `#` or `$` inside a value (`edit "net # 42"`, a comment line, a
  password prompt inside a transcript) survives byte for byte, because the cleaner never looks there.

Anchoring on the prompt found at the beginning is the point: a configuration line that happens to
carry `#` must not be at risk, and by construction it cannot be.

## The table

| Platform | Prompt cleaning |
|---|---|
| `fortios`, alias `fortinet` | `^([^#$\n]+ [#$] )` |
| `exos`, alias `extreme_exos` | the same |
| everything else | no-op, the text is returned unchanged |

The two spellings are the two vocabularies of the family: the auditor names platforms `fortios` and
`exos`, the helper catalogue names the same devices `fortinet` and `extreme_exos`. `ALIASES` maps the
second spelling onto the first so a caller can pass whichever name it already holds, and
`prefix(platform)` answers `None` for anything the table does not name - including a value that is not
a string.

## Who cleans what

- **auditor**, `collect.py`: every step of the SSH step table is marked `prompt=True`, so the
  preflight field is read through the cleaned text and the snapshot is the cleaned text. This is why
  `ChannelEvent.response_sha256` (the raw answer) and `Snapshot.sha256` (the cleaned text) differ on a
  device that prints a prompt; see
  [`../../netops-auditor/docs/channels.md`](../../netops-auditor/docs/channels.md).
- **helper**, `engine._exec_read`: applied to the answer of every exec platform, which is a no-op
  wherever the table holds nothing. The pseudo-terminal path of a device without an exec channel is
  not touched: it strips its own prompt as part of driving the terminal.

Before this module the auditor carried the rule alone, with `^([^#\n]+# )` - it knew `#` only. Under a
read-only account the `$` prompt stayed in the snapshot and in its hash, and the preflight would have
read `<hostname> $ output` instead of `output`.
