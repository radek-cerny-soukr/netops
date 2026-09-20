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

`FIELDS` is `operation_id`, `device`, `status`, `channel`, `request`, `response_sha256`,
`response_bytes`, `started_at`, `finished_at`, `legacy_ssh`, `detail`, `query`, `platform`, `port`,
`count`, `item_count`, `offset`, `max_bytes`, `total_bytes`, `returned_bytes`, `path_sha256`,
`result_sha256`, `use_tls`, `plaintext_acknowledged`, `pagination_source`, `transport`, `rc`.

A response is recorded by its length and its SHA-256, never by its content: `response_sha256` and
`response_bytes` say that the same answer came back twice without the file holding either answer.

## Persistence

| Property | Behaviour |
|---|---|
| mode | the file is created with mode 0600 |
| durability | each record is written and flushed, and the file is fsynced before the call returns |
| exclusion | an advisory `flock` on a stable lock file beside the log covers the size check, the whole rotation and the write, so writers in different processes cannot interleave a line or rotate the same file at once; a `threading.Lock` does the same inside one process |
| rotation | a segment larger than `segment_bytes` is rotated; `retained_segments` files are kept in total, the active one and `retained_segments - 1` rotated ones, and the oldest is removed |

The lock file is the log's name with a leading dot and a `.lock` suffix - `audit.jsonl` is locked
through `.audit.jsonl.lock` - so it is never mistaken for a segment and its name does not move when
the log rotates. Locking the log itself would not do: rotation renames that file, and two processes
would end up holding locks on two different inodes. The lock is advisory, which is enough because
every writer goes through this module; it does not protect the log from a process that writes to it
without one.

A write that cannot be completed raises `AuditPersistenceError`: a run whose record cannot be written
fails rather than continuing unrecorded.

## What is refused

| Situation | Refusal |
|---|---|
| unknown field name | `AuditFieldError` naming the field |
| `status` outside `STATUSES` | `AuditFieldError` naming the value and the three statuses |
| `operation_id` of another shape | `AuditFieldError` naming the value and the expected shape |
| component outside the three names | refused when the recorder is built |
| the file cannot be written, locked, or rotated | `AuditPersistenceError` |
