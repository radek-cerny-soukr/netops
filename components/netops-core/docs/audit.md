# Audit record

`netops_core.audit` writes what a component did, as one JSON object per line, in an append-only file
that rotates. It is a record of operations, not a log of everything: the fields are a closed set, and a
field that is not in it is a programming error rather than a line that is silently dropped.

## Recorder

```
Recorder(path, component, segment_bytes=2_000_000, retained_segments=5)
record(event, **fields)
path()
lock_path()
```

`component` must be one of `("helper", "auditor", "admin")`; any other value is refused when the
recorder is built, naming the value and the three that are allowed.

## Record

Every record is `{"timestamp": <UTC>, "component": <component>, "event": <event>, **fields}`,
serialized with `separators=(",", ":")` and `sort_keys=True`, followed by a newline. One record is one
line: a reader can split the file on newlines without parsing it.

| Field | Rule |
|---|---|
| any field name | must be in `FIELDS`; an unknown name raises `AuditFieldError` naming it |
| `status` | when present, one of `STATUSES = ("started", "ok", "failed")` |
| `operation_id` | when present, matches `op_[0-9a-f]{32}` |

`FIELDS` is `channel`, `count`, `detail`, `device`, `finished_at`, `item_count`, `legacy_ssh`, `max_bytes`, `offset`, `operation_id`, `pagination_source`, `path_sha256`, `plaintext_acknowledged`, `platform`, `port`, `query`, `rc`, `recipe`, `request`, `response_bytes`, `response_sha256`, `result_sha256`, `returned_bytes`, `started_at`, `status`, `timeout`, `total_bytes`, `transport`, `use_tls`.

`recipe` and `timeout` are optional diagnostic metadata accepted by the recorder. The
recorder checks the closed set of field names, plus the `status` and `operation_id`
constraints above; it does not apply diagnostic recipe or timeout argument validation.
The calling component validates its inputs before recording them, and supplied values
must still be JSON serializable. Unknown field names are rejected before any write.

A response is recorded by its length and its SHA-256, never by its content: `response_sha256` and
`response_bytes` say that the same answer came back twice without the file holding either answer.

## Persistence

| Property | Behaviour |
|---|---|
| mode | the file is created with mode 0600 |
| links | the log, its lock and the log reopened after a rotation are opened with `O_NOFOLLOW` and must be regular files owned by the user of the process with exactly one hard link (rotation renames, it never adds a second link); only then is mode 0600 set, on the open descriptor |
| durability | each record is written with `write(2)` straight to the descriptor, and the file is fsynced before the call returns |
| exclusion | an advisory `flock` on a stable lock file beside the log covers the size check, the whole rotation and the write, so writers in different processes cannot interleave a line or rotate the same file at once; a `threading.Lock` does the same inside one process |
| rotation | a segment is rotated before a write that would make it exceed `segment_bytes`, so no segment grows past it; a single record larger than `segment_bytes` is refused with `AuditPersistenceError`; `retained_segments` files are kept in total, the active one and `retained_segments - 1` rotated ones, and the oldest is removed. Rotation is a series of renames that loses nothing when it is interrupted: the oldest segment is removed only when every rotated slot is taken; when a slot is free - one that an interrupted rotation emptied - the newer segments move up into it and nothing is removed. The directory is fsynced after the renames |

The lock file is the log's name with a leading dot and a `.lock` suffix - `audit.jsonl` is locked
through `.audit.jsonl.lock` - so it is never mistaken for a segment and its name does not move when
the log rotates. Locking the log itself would not do: rotation renames that file, and two processes
would end up holding locks on two different inodes. The lock is advisory, which is enough because
every writer goes through this module; it does not protect the log from a process that writes to it
without one.

A write that cannot be completed raises `AuditPersistenceError`: a run whose record cannot be written
fails rather than continuing unrecorded. A write that fails part way, for example on a full disk
(`ENOSPC`) or at a file size limit (`EFBIG`), is first cut back, under the same lock, to the size the
file had before it began, so no fragment of the refused record stays in front of the next one. A log
that already ends without a newline - a writer killed in the middle of a record leaves such a fragment -
receives a newline before the next record: the fragment stays one unreadable line of its own and the
record after it is still one line.

A process killed in the middle of a rotation leaves a gap: one rotated name, `audit.jsonl.1` for
example, is missing while the older ones are in place. The next write that rotates finds the lowest
free slot and only moves the newer segments into it, so after it every segment that was kept before the
interrupted rotation is still kept, and the oldest is removed only when a later rotation needs its slot.

## What is refused

| Situation | Refusal |
|---|---|
| unknown field name | `AuditFieldError` naming the field |
| `status` outside `STATUSES` | `AuditFieldError` naming the value and the three statuses |
| `operation_id` of another shape | `AuditFieldError` naming the value and the expected shape |
| component outside the three names | refused when the recorder is built |
| the file cannot be written, locked, or rotated | `AuditPersistenceError` |
| a record larger than `segment_bytes` | `AuditPersistenceError` naming the record size and the limit |
| the log or its lock is a symbolic link, a hard link (more than one name), not a regular file, or owned by another user | `AuditPersistenceError`; the target of the link is neither written nor has its mode changed |
