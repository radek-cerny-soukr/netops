from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from .findings import fingerprint_of
from .state import evaluation_complete

MOMENT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SCHEMA_VERSION = 2
PREVIOUS_SCHEMA_VERSION = 1
MIGRATE_COMMAND = "netops-auditor migrate-store --store <file>"

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY,
        tenant TEXT NOT NULL,
        device TEXT NOT NULL,
        started_at TEXT NOT NULL,
        snapshot_sha256 TEXT NOT NULL,
        snapshot_source TEXT NOT NULL,
        rules_version TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY,
        run_id INTEGER NOT NULL REFERENCES runs(id),
        fingerprint TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        rule_version INTEGER NOT NULL,
        device TEXT NOT NULL,
        object_key TEXT NOT NULL,
        severity TEXT NOT NULL,
        "class" TEXT NOT NULL,
        section TEXT NOT NULL,
        line INTEGER NOT NULL,
        evidence TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS findings_run_id ON findings(run_id)",
    "CREATE INDEX IF NOT EXISTS findings_fingerprint ON findings(fingerprint)",
    """CREATE TABLE IF NOT EXISTS baseline (
        id INTEGER PRIMARY KEY,
        tenant TEXT NOT NULL,
        device TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        object_key TEXT NOT NULL,
        accepted_at TEXT NOT NULL,
        accepted_by TEXT NOT NULL,
        note TEXT NOT NULL,
        run_id INTEGER NOT NULL REFERENCES runs(id)
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS baseline_tenant_device_fingerprint ON baseline(tenant, device, fingerprint)",
    "CREATE INDEX IF NOT EXISTS baseline_tenant_device ON baseline(tenant, device)",
    """CREATE TABLE IF NOT EXISTS channel_events (
        id INTEGER PRIMARY KEY,
        tenant TEXT NOT NULL,
        device TEXT NOT NULL,
        run_id INTEGER REFERENCES runs(id),
        channel TEXT NOT NULL,
        request TEXT NOT NULL,
        response_sha256 TEXT NOT NULL,
        response_bytes INTEGER NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        outcome TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS channel_events_tenant_device ON channel_events(tenant, device)",
    "CREATE INDEX IF NOT EXISTS channel_events_run_id ON channel_events(run_id)",
)

RUN_COLUMNS = "id, tenant, device, started_at, snapshot_sha256, snapshot_source, rules_version"

FINDING_COLUMNS = (
    "findings.rule_id, findings.rule_version, findings.device, findings.object_key, findings.severity,"
    ' findings."class", findings.section, findings.line, findings.evidence, findings.fingerprint'
)

BASELINE_COLUMNS = "fingerprint, rule_id, object_key, accepted_at, accepted_by, note, run_id"

_INSERT_RUN = (
    "INSERT INTO runs (tenant, device, started_at, snapshot_sha256, snapshot_source, rules_version)"
    " VALUES (?, ?, ?, ?, ?, ?)"
)

_INSERT_FINDING = (
    "INSERT INTO findings"
    ' (run_id, fingerprint, rule_id, rule_version, device, object_key, severity, "class", section, line, evidence)'
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_SELECT_FINDINGS = (
    "SELECT %s FROM findings JOIN runs ON runs.id = findings.run_id"
    " WHERE findings.run_id = ? AND runs.tenant = ?"
    " ORDER BY findings.rule_id, findings.object_key, findings.id"
) % FINDING_COLUMNS

_SELECT_RUN = "SELECT tenant, device FROM runs WHERE id = ?"

_SELECT_RUN_IDENTITIES = (
    "SELECT fingerprint, rule_id, object_key FROM findings WHERE run_id = ?"
    " ORDER BY rule_id, object_key, id"
)

_INSERT_BASELINE = (
    "INSERT OR IGNORE INTO baseline"
    " (tenant, device, fingerprint, rule_id, object_key, accepted_at, accepted_by, note, run_id)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_SELECT_BASELINE = (
    "SELECT %s FROM baseline WHERE tenant = ? AND device = ? ORDER BY rule_id, object_key, id"
) % BASELINE_COLUMNS

_SELECT_BASELINE_FINGERPRINTS = "SELECT fingerprint FROM baseline WHERE tenant = ? AND device = ?"

_DELETE_BASELINE = "DELETE FROM baseline WHERE tenant = ? AND device = ? AND fingerprint = ?"

OUTCOME_OK = "ok"
OUTCOME_FAILED = "failed"
OUTCOMES = (OUTCOME_OK, OUTCOME_FAILED)

CHANNEL_EVENT_FIELDS = (
    "device",
    "channel",
    "request",
    "response_sha256",
    "response_bytes",
    "started_at",
    "finished_at",
    "outcome",
)

CHANNEL_EVENT_COLUMNS = (
    "id, tenant, device, run_id, channel, request, response_sha256, response_bytes,"
    " started_at, finished_at, outcome"
)

_INSERT_CHANNEL_EVENT = (
    "INSERT INTO channel_events"
    " (tenant, device, run_id, channel, request, response_sha256, response_bytes,"
    " started_at, finished_at, outcome)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_SELECT_CHANNEL_EVENTS = (
    "SELECT %s FROM channel_events WHERE tenant = ? AND device = ?"
    " ORDER BY started_at DESC, id DESC"
) % CHANNEL_EVENT_COLUMNS

_SELECT_CHANNEL_EVENTS_FOR_RUN = (
    "SELECT %s FROM channel_events WHERE tenant = ? AND run_id = ? ORDER BY id"
) % CHANNEL_EVENT_COLUMNS


class StoreError(Exception):
    pass


def _has_schema(connection) -> bool:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'runs'"
    ).fetchone()
    return row is not None


def schema_version(connection) -> int:
    if not _has_schema(connection):
        return 0
    return int(connection.execute("PRAGMA user_version").fetchone()[0]) or PREVIOUS_SCHEMA_VERSION


def checked_schema(connection) -> int:
    version = schema_version(connection)
    if version in (0, SCHEMA_VERSION):
        return version
    raise StoreError(
        "store schema version %d, expected %d: the fingerprint of a finding carries the tenant"
        " since version %d; migrate the store with %s"
        % (version, SCHEMA_VERSION, SCHEMA_VERSION, MIGRATE_COMMAND)
    )


_SELECT_MIGRATED_FINDINGS = (
    "SELECT findings.id, findings.fingerprint, findings.rule_id, findings.rule_version,"
    " findings.device, findings.object_key, runs.tenant FROM findings"
    " LEFT JOIN runs ON runs.id = findings.run_id ORDER BY findings.id"
)

_SELECT_MIGRATED_BASELINE = "SELECT id, tenant, fingerprint FROM baseline ORDER BY id"


def _migrated_findings(connection) -> tuple:
    mapping, count = {}, 0
    for row in connection.execute(_SELECT_MIGRATED_FINDINGS).fetchall():
        tenant = row["tenant"]
        if not isinstance(tenant, str) or not tenant.strip():
            raise StoreError(
                "finding %d belongs to no run that names a tenant, the store cannot be migrated"
                % row["id"]
            )
        fresh = fingerprint_of(
            row["rule_id"], row["rule_version"], tenant, row["device"], row["object_key"]
        )
        mapping[(tenant, row["fingerprint"])] = fresh
        connection.execute("UPDATE findings SET fingerprint = ? WHERE id = ?", (fresh, row["id"]))
        count += 1
    return mapping, count


def _migrated_baseline(connection, mapping) -> int:
    count = 0
    for row in connection.execute(_SELECT_MIGRATED_BASELINE).fetchall():
        fresh = mapping.get((row["tenant"], row["fingerprint"]))
        if fresh is None:
            raise StoreError(
                "baseline entry %d names a fingerprint no finding of its tenant carries, the store"
                " cannot be migrated" % row["id"]
            )
        connection.execute("UPDATE baseline SET fingerprint = ? WHERE id = ?", (fresh, row["id"]))
        count += 1
    return count


def migrate(path) -> dict:
    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        version = schema_version(connection)
        if version == 0:
            raise StoreError("store %s holds no audit schema" % path)
        if version == SCHEMA_VERSION:
            raise StoreError("store %s already holds schema version %d" % (path, SCHEMA_VERSION))
        if version != PREVIOUS_SCHEMA_VERSION:
            raise StoreError(
                "store %s holds schema version %d, the migration reads version %d"
                % (path, version, PREVIOUS_SCHEMA_VERSION)
            )
        connection.execute("BEGIN IMMEDIATE")
        try:
            mapping, findings = _migrated_findings(connection)
            baseline = _migrated_baseline(connection, mapping)
            connection.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
    finally:
        connection.close()
    return {"findings": findings, "baseline": baseline}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime(MOMENT_FORMAT)


def _checked_moment(value, name: str = "started_at") -> str:
    try:
        parsed = datetime.strptime(value, MOMENT_FORMAT)
    except (TypeError, ValueError):
        raise StoreError("%s is not ISO 8601 UTC (%s): %r" % (name, MOMENT_FORMAT, value))
    if parsed.strftime(MOMENT_FORMAT) != value:
        raise StoreError("%s is not ISO 8601 UTC (%s): %r" % (name, MOMENT_FORMAT, value))
    return value


def _checked_text(name: str, value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StoreError("%s must be a non-empty string, got %r" % (name, value))
    return value


def _checked_count(name: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StoreError("%s must be a non-negative whole number, got %r" % (name, value))
    return value


def _checked_outcome(value) -> str:
    if not isinstance(value, str) or value not in OUTCOMES:
        raise StoreError("outcome must be one of %r, got %r" % (OUTCOMES, value))
    return value


def _checked_event(event, device: str) -> dict:
    values = dict((name, getattr(event, name, None)) for name in CHANNEL_EVENT_FIELDS)
    _checked_text("device", values["device"])
    _checked_text("channel", values["channel"])
    _checked_text("request", values["request"])
    _checked_text("response_sha256", values["response_sha256"])
    _checked_count("response_bytes", values["response_bytes"])
    _checked_moment(values["started_at"], "started_at")
    _checked_moment(values["finished_at"], "finished_at")
    _checked_outcome(values["outcome"])
    if values["device"] != device:
        raise StoreError(
            "channel event belongs to device %r, call covers device %r" % (values["device"], device)
        )
    return values


def _row_to_finding(row) -> dict:
    item = dict(row)
    item["evidence"] = json.loads(item["evidence"])
    return item


class Store:
    def __init__(self, path):
        self._connection = sqlite3.connect(str(path), isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        try:
            checked_schema(self._connection)
        except StoreError:
            self._connection.close()
            raise
        for statement in SCHEMA:
            self._connection.execute(statement)
        self._connection.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)

    def close(self):
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def record_run(
        self,
        tenant,
        device,
        snapshot_sha256,
        snapshot_source,
        rules_version,
        findings,
        started_at=None,
    ) -> int:
        _checked_text("tenant", tenant)
        _checked_text("device", device)
        _checked_text("snapshot_sha256", snapshot_sha256)
        _checked_text("snapshot_source", snapshot_source)
        _checked_text("rules_version", rules_version)
        moment = _now_utc() if started_at is None else _checked_moment(started_at)
        connection = self._connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            run_id = connection.execute(
                _INSERT_RUN,
                (tenant, device, moment, snapshot_sha256, snapshot_source, rules_version),
            ).lastrowid
            for finding in findings:
                item = finding.as_dict()
                if item["device"] != device:
                    raise StoreError(
                        "finding belongs to device %r, run covers device %r" % (item["device"], device)
                    )
                if item["tenant"] != tenant:
                    raise StoreError(
                        "finding belongs to tenant %r, run covers tenant %r" % (item["tenant"], tenant)
                    )
                connection.execute(
                    _INSERT_FINDING,
                    (
                        run_id,
                        item["fingerprint"],
                        item["rule_id"],
                        item["rule_version"],
                        item["device"],
                        item["object_key"],
                        item["severity"],
                        item["class"],
                        item["section"],
                        item["line"],
                        json.dumps(item["evidence"], ensure_ascii=False, sort_keys=True),
                    ),
                )
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        return run_id

    def findings_for_run(self, tenant, run_id) -> tuple:
        rows = self._connection.execute(_SELECT_FINDINGS, (run_id, tenant)).fetchall()
        return tuple(_row_to_finding(row) for row in rows)

    def last_run(self, tenant, device):
        row = self._connection.execute(
            "SELECT %s FROM runs WHERE tenant = ? AND device = ? ORDER BY started_at DESC, id DESC LIMIT 1" % RUN_COLUMNS,
            (tenant, device),
        ).fetchone()
        return None if row is None else dict(row)

    def runs_for_device(self, tenant, device) -> tuple:
        rows = self._connection.execute(
            "SELECT %s FROM runs WHERE tenant = ? AND device = ? ORDER BY started_at DESC, id DESC" % RUN_COLUMNS,
            (tenant, device),
        ).fetchall()
        return tuple(dict(row) for row in rows)

    def accept_baseline(self, tenant, device, run_id, accepted_by, note, accepted_at=None) -> int:
        _checked_text("tenant", tenant)
        _checked_text("device", device)
        _checked_text("accepted_by", accepted_by)
        _checked_text("note", note)
        moment = _now_utc() if accepted_at is None else _checked_moment(accepted_at, "accepted_at")
        connection = self._connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            run = connection.execute(_SELECT_RUN, (run_id,)).fetchone()
            if run is None:
                raise StoreError("run %r does not exist" % (run_id,))
            if run["tenant"] != tenant:
                raise StoreError("run %r belongs to another tenant than %r" % (run_id, tenant))
            if run["device"] != device:
                raise StoreError("run %r covers device %r, not %r" % (run_id, run["device"], device))
            identities = connection.execute(_SELECT_RUN_IDENTITIES, (run_id,)).fetchall()
            if not evaluation_complete(identities):
                raise StoreError("cannot accept a baseline from an unevaluated audit")
            before = connection.total_changes
            for item in identities:
                connection.execute(
                    _INSERT_BASELINE,
                    (
                        tenant,
                        device,
                        item["fingerprint"],
                        item["rule_id"],
                        item["object_key"],
                        moment,
                        accepted_by,
                        note,
                        run_id,
                    ),
                )
            accepted = connection.total_changes - before
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        return accepted

    def baseline_fingerprints(self, tenant, device) -> frozenset:
        rows = self._connection.execute(_SELECT_BASELINE_FINGERPRINTS, (tenant, device)).fetchall()
        return frozenset(row["fingerprint"] for row in rows)

    def baseline_entries(self, tenant, device) -> tuple:
        rows = self._connection.execute(_SELECT_BASELINE, (tenant, device)).fetchall()
        return tuple(dict(row) for row in rows)

    def forget_baseline(self, tenant, device, fingerprint) -> bool:
        _checked_text("tenant", tenant)
        _checked_text("device", device)
        _checked_text("fingerprint", fingerprint)
        connection = self._connection
        before = connection.total_changes
        connection.execute(_DELETE_BASELINE, (tenant, device, fingerprint))
        return connection.total_changes > before

    def record_channel_events(self, tenant, device, events, run_id=None) -> int:
        _checked_text("tenant", tenant)
        _checked_text("device", device)
        connection = self._connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            if run_id is not None:
                run = connection.execute(_SELECT_RUN, (run_id,)).fetchone()
                if run is None:
                    raise StoreError("run %r does not exist" % (run_id,))
                if run["tenant"] != tenant:
                    raise StoreError("run %r belongs to another tenant than %r" % (run_id, tenant))
                if run["device"] != device:
                    raise StoreError("run %r covers device %r, not %r" % (run_id, run["device"], device))
            written = 0
            for event in events:
                values = _checked_event(event, device)
                connection.execute(
                    _INSERT_CHANNEL_EVENT,
                    (
                        tenant,
                        values["device"],
                        run_id,
                        values["channel"],
                        values["request"],
                        values["response_sha256"],
                        values["response_bytes"],
                        values["started_at"],
                        values["finished_at"],
                        values["outcome"],
                    ),
                )
                written += 1
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        return written

    def channel_events(self, tenant, device, limit=None) -> tuple:
        statement = _SELECT_CHANNEL_EVENTS
        parameters = (tenant, device)
        if limit is not None:
            statement = statement + " LIMIT ?"
            parameters = (tenant, device, _checked_count("limit", limit))
        rows = self._connection.execute(statement, parameters).fetchall()
        return tuple(dict(row) for row in rows)

    def channel_events_for_run(self, tenant, run_id) -> tuple:
        rows = self._connection.execute(_SELECT_CHANNEL_EVENTS_FOR_RUN, (tenant, run_id)).fetchall()
        return tuple(dict(row) for row in rows)
