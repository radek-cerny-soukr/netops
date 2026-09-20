import sqlite3
from datetime import datetime
from types import SimpleNamespace

import pytest

from netops_auditor.findings import Finding, fingerprint_of, fingerprint_v1
from netops_auditor.store import (
    MIGRATE_COMMAND,
    PREVIOUS_SCHEMA_VERSION,
    SCHEMA_VERSION,
    Store,
    StoreError,
    migrate,
    schema_version,
)

TENANT = "tenant-a"
DEVICE = "fw-a.example.invalid"
SNAPSHOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SOURCE = "snapshots/fw-a.example.invalid/2026-09-12.conf"
RULES_VERSION = "catalog-2026-09-01"

RUN_SCHEMA = ("id", "tenant", "device", "started_at", "snapshot_sha256", "snapshot_source", "rules_version")

FINDING_SCHEMA = (
    "id",
    "run_id",
    "fingerprint",
    "rule_id",
    "rule_version",
    "device",
    "object_key",
    "severity",
    "class",
    "section",
    "line",
    "evidence",
)

INSERT_FINDING = (
    "INSERT INTO findings"
    ' (run_id, fingerprint, rule_id, rule_version, device, object_key, severity, "class", section, line, evidence)'
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def make_finding(rule_id="L1-001", object_key="firewall policy/1", evidence=(("srcaddr", "192.0.2.0/24"),), device=DEVICE, tenant=TENANT):
    return Finding(
        rule_id=rule_id,
        rule_version=1,
        tenant=tenant,
        device=device,
        object_key=object_key,
        severity="high",
        rule_class="fakt",
        section="firewall policy",
        line=12,
        evidence=evidence,
    )


def record(store, findings=(), tenant=TENANT, device=DEVICE, started_at=None, sha=SNAPSHOT, source=SOURCE, rules=RULES_VERSION):
    return store.record_run(tenant, device, sha, source, rules, findings, started_at=started_at)


def columns(store, table):
    rows = store._connection.execute("PRAGMA table_info(%s)" % table).fetchall()
    return tuple(row["name"] for row in rows)


def test_schema_is_created_over_empty_file_and_survives_reopen(tmp_path):
    path = tmp_path / "audit.db"
    path.write_bytes(b"")
    with Store(path) as store:
        run_id = record(store, (make_finding(),))
    with Store(path) as store:
        assert columns(store, "runs") == RUN_SCHEMA
        assert store.last_run(TENANT, DEVICE)["id"] == run_id
        assert len(store.findings_for_run(TENANT, run_id)) == 1
        second = record(store, (make_finding(rule_id="L1-002"),))
    assert second != run_id


def test_schema_keeps_no_configuration_and_has_both_indexes():
    with Store(":memory:") as store:
        assert columns(store, "runs") == RUN_SCHEMA
        assert columns(store, "findings") == FINDING_SCHEMA
        indexes = store._connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'findings' ORDER BY name"
        ).fetchall()
        assert tuple(row["name"] for row in indexes) == ("findings_fingerprint", "findings_run_id")


def test_finding_round_trips_as_dict():
    item = make_finding()
    stored = {key: value for key, value in item.as_dict().items() if key != "tenant"}
    with Store(":memory:") as store:
        run_id = record(store, (item,))
        assert store.findings_for_run(TENANT, run_id) == (stored,)
        assert store.last_run(TENANT, DEVICE)["tenant"] == item.tenant
        assert store.findings_for_run(TENANT, run_id + 1000) == ()


def test_a_finding_of_another_tenant_never_enters_a_run():
    with Store(":memory:") as store:
        with pytest.raises(StoreError, match="finding belongs to tenant"):
            record(store, (make_finding(tenant="tenant-b"),), tenant="tenant-a")
        assert store.last_run("tenant-a", DEVICE) is None


def test_run_metadata_is_read_back():
    with Store(":memory:") as store:
        run_id = record(store, started_at="2026-09-12T05:00:00Z")
        run = store.last_run(TENANT, DEVICE)
    assert run == {
        "id": run_id,
        "tenant": TENANT,
        "device": DEVICE,
        "started_at": "2026-09-12T05:00:00Z",
        "snapshot_sha256": SNAPSHOT,
        "snapshot_source": SOURCE,
        "rules_version": RULES_VERSION,
    }


def test_started_at_defaults_to_utc_with_zulu_suffix():
    with Store(":memory:") as store:
        record(store)
        moment = store.last_run(TENANT, DEVICE)["started_at"]
    assert moment.endswith("Z")
    assert datetime.strptime(moment, "%Y-%m-%dT%H:%M:%SZ").year >= 2026


def test_findings_order_is_deterministic():
    items = (
        make_finding(rule_id="L1-002", object_key="firewall policy/9"),
        make_finding(rule_id="L1-001", object_key="firewall policy/9"),
        make_finding(rule_id="L1-002", object_key="firewall policy/1"),
        make_finding(rule_id="L1-001", object_key="firewall policy/1"),
    )
    with Store(":memory:") as store:
        run_id = record(store, items)
        first = tuple((f["rule_id"], f["object_key"]) for f in store.findings_for_run(TENANT, run_id))
        second = tuple((f["rule_id"], f["object_key"]) for f in store.findings_for_run(TENANT, run_id))
    assert first == (
        ("L1-001", "firewall policy/1"),
        ("L1-001", "firewall policy/9"),
        ("L1-002", "firewall policy/1"),
        ("L1-002", "firewall policy/9"),
    )
    assert first == second


def test_evidence_survives_diacritics_quotes_and_scalars():
    evidence = (
        ("dstaddr", "198.51.100.0/24"),
        ("hits", 0),
        ("popis", """pravidlo "any-any" na rozhraní wan1, příliš široké"""),
        ("utm", False),
    )
    with Store(":memory:") as store:
        run_id = record(store, (make_finding(evidence=evidence),))
        stored = store.findings_for_run(TENANT, run_id)[0]["evidence"]
    assert stored == dict(evidence)
    assert stored["utm"] is False
    assert stored["hits"] == 0


def test_last_run_and_history_are_ordered_newest_first():
    with Store(":memory:") as store:
        old = record(store, started_at="2026-09-01T05:00:00Z")
        newest = record(store, started_at="2026-09-11T05:00:00Z")
        middle = record(store, started_at="2026-09-05T05:00:00Z")
        assert store.last_run(TENANT, DEVICE)["id"] == newest
        assert tuple(run["id"] for run in store.runs_for_device(TENANT, DEVICE)) == (newest, middle, old)


def test_unknown_device_has_no_history():
    with Store(":memory:") as store:
        record(store)
        assert store.last_run(TENANT, "fw-z.example.invalid") is None
        assert store.runs_for_device(TENANT, "fw-z.example.invalid") == ()


def test_tenant_isolation_on_the_same_device_name():
    with Store(":memory:") as store:
        mine = record(store, tenant="tenant-a", started_at="2026-09-01T05:00:00Z")
        record(store, tenant="tenant-b", started_at="2026-09-10T05:00:00Z")
        last = store.last_run("tenant-a", DEVICE)
        assert last["id"] == mine
        assert last["tenant"] == "tenant-a"
        assert tuple(run["id"] for run in store.runs_for_device("tenant-a", DEVICE)) == (mine,)
        assert store.last_run("tenant-c", DEVICE) is None
        assert store.runs_for_device("tenant-c", DEVICE) == ()


def test_findings_for_run_is_scoped_to_the_tenant():
    with Store(":memory:") as store:
        mine = record(store, (make_finding(tenant="tenant-a"),), tenant="tenant-a")
        theirs = record(
            store, (make_finding(rule_id="L1-002", tenant="tenant-b"),), tenant="tenant-b"
        )
        assert len(store.findings_for_run("tenant-a", mine)) == 1
        assert store.findings_for_run("tenant-b", mine) == ()
        assert store.findings_for_run("tenant-a", theirs) == ()
        assert len(store.findings_for_run("tenant-b", theirs)) == 1


def test_failed_finding_write_leaves_no_run_behind():
    broken = make_finding(rule_id="L1-002", object_key="firewall policy/2", evidence=(("blob", object()),))
    with Store(":memory:") as store:
        with pytest.raises(TypeError):
            record(store, (make_finding(), broken))
        assert store.runs_for_device(TENANT, DEVICE) == ()
        assert store._connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 0
        assert store._connection.execute("SELECT count(*) FROM findings").fetchone()[0] == 0
        run_id = record(store, (make_finding(),))
        assert len(store.findings_for_run(TENANT, run_id)) == 1


def test_finding_about_another_device_is_refused_and_rolled_back():
    stray = make_finding(rule_id="L1-002", object_key="firewall policy/2", device="fw-b.example.invalid")
    with Store(":memory:") as store:
        with pytest.raises(StoreError):
            record(store, (make_finding(), stray))
        assert store.runs_for_device(TENANT, DEVICE) == ()
        assert store._connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 0
        assert store._connection.execute("SELECT count(*) FROM findings").fetchone()[0] == 0
        run_id = record(store, (make_finding(),))
        assert len(store.findings_for_run(TENANT, run_id)) == 1


@pytest.mark.parametrize("field", ("sha", "source", "rules"))
@pytest.mark.parametrize("value", ("", "   ", "\t\n", None))
def test_run_without_snapshot_provenance_is_refused(field, value):
    with Store(":memory:") as store:
        with pytest.raises(StoreError):
            record(store, (make_finding(),), **{field: value})
        assert store.runs_for_device(TENANT, DEVICE) == ()
        assert store._connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 0


@pytest.mark.parametrize("field", ("tenant", "device"))
@pytest.mark.parametrize("value", ("", "   ", "\t\n", None))
def test_run_without_owner_or_device_is_refused(field, value):
    with Store(":memory:") as store:
        with pytest.raises(StoreError):
            record(store, **{field: value})
        assert store._connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 0


@pytest.mark.parametrize(
    "moment",
    (
        "vcera",
        "",
        "2026-09-12",
        "2026-09-12T05:00:00",
        "2026-09-12T05:00:00+00:00",
        "2026-09-12T05:00:00.123456Z",
        "2026-9-1T5:00:00Z",
        "9999",
        20260912,
    ),
)
def test_started_at_must_be_iso_utc_with_zulu_suffix(moment):
    with Store(":memory:") as store:
        good = record(store, started_at="2026-09-01T05:00:00Z")
        with pytest.raises(StoreError):
            record(store, started_at=moment)
        assert store.last_run(TENANT, DEVICE)["id"] == good
        assert store._connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 1


def test_generated_started_at_passes_its_own_validation():
    with Store(":memory:") as store:
        record(store)
        generated = store.last_run(TENANT, DEVICE)["started_at"]
        second = record(store, started_at=generated)
    assert second is not None


def test_foreign_keys_are_enforced():
    with Store(":memory:") as store:
        assert store._connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                INSERT_FINDING,
                (4242, "0" * 64, "L1-001", 1, DEVICE, "firewall policy/1", "high", "fakt", "firewall policy", 12, "{}"),
            )


def test_context_manager_closes_the_connection(tmp_path):
    store = Store(tmp_path / "audit.db")
    with store:
        record(store)
    with pytest.raises(sqlite3.ProgrammingError):
        store.last_run(TENANT, DEVICE)


BASELINE_SCHEMA = (
    "id",
    "tenant",
    "device",
    "fingerprint",
    "rule_id",
    "object_key",
    "accepted_at",
    "accepted_by",
    "note",
    "run_id",
)

ACCEPTED_BY = "radek"
NOTE = "znamy stav, resime pozdeji"

INSERT_BASELINE = (
    "INSERT INTO baseline"
    " (tenant, device, fingerprint, rule_id, object_key, accepted_at, accepted_by, note, run_id)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


class FlakyConnection:
    def __init__(self, connection, fail_on):
        self._connection = connection
        self._fail_on = fail_on
        self._writes = 0

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def execute(self, statement, *args):
        if "INTO baseline" in statement:
            self._writes += 1
            if self._writes == self._fail_on:
                raise RuntimeError("zapis selhal")
        return self._connection.execute(statement, *args)


def accept(store, run_id, tenant=TENANT, device=DEVICE, accepted_by=ACCEPTED_BY, note=NOTE, accepted_at=None):
    return store.accept_baseline(tenant, device, run_id, accepted_by, note, accepted_at=accepted_at)


def baseline_count(store):
    return store._connection.execute("SELECT count(*) FROM baseline").fetchone()[0]


def trio():
    return (
        make_finding(rule_id="L1-002", object_key="firewall policy/9"),
        make_finding(rule_id="L1-001", object_key="firewall policy/1"),
        make_finding(rule_id="L1-001", object_key="firewall policy/9"),
    )


def test_baseline_schema_has_its_columns_and_a_unique_identity_index():
    with Store(":memory:") as store:
        assert columns(store, "baseline") == BASELINE_SCHEMA
        indexes = store._connection.execute("PRAGMA index_list(baseline)").fetchall()
        flags = dict((row["name"], row["unique"]) for row in indexes)
        assert flags.get("baseline_tenant_device_fingerprint") == 1
        assert flags.get("baseline_tenant_device") == 0
        identity = store._connection.execute(
            "PRAGMA index_info(baseline_tenant_device_fingerprint)"
        ).fetchall()
        assert tuple(row["name"] for row in identity) == ("tenant", "device", "fingerprint")


def test_duplicate_baseline_entry_is_refused_by_the_schema():
    item = make_finding()
    with Store(":memory:") as store:
        run_id = record(store, (item,))
        accept(store, run_id)
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                INSERT_BASELINE,
                (
                    TENANT,
                    DEVICE,
                    item.fingerprint(),
                    "L1-001",
                    "firewall policy/1",
                    "2026-09-12T05:00:00Z",
                    ACCEPTED_BY,
                    NOTE,
                    run_id,
                ),
            )
        assert baseline_count(store) == 1


def test_baseline_run_id_is_a_foreign_key():
    with Store(":memory:") as store:
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                INSERT_BASELINE,
                (
                    TENANT,
                    DEVICE,
                    "0" * 64,
                    "L1-001",
                    "firewall policy/1",
                    "2026-09-12T05:00:00Z",
                    ACCEPTED_BY,
                    NOTE,
                    4242,
                ),
            )


def test_accept_baseline_takes_every_finding_of_the_run():
    items = trio()
    with Store(":memory:") as store:
        run_id = record(store, items)
        assert accept(store, run_id) == 3
        assert store.baseline_fingerprints(TENANT, DEVICE) == frozenset(item.fingerprint() for item in items)
        assert baseline_count(store) == 3


def test_baseline_entry_records_who_why_when_and_the_run():
    item = make_finding()
    with Store(":memory:") as store:
        run_id = record(store, (item,))
        accept(store, run_id, accepted_at="2026-09-12T05:00:00Z")
        entries = store.baseline_entries(TENANT, DEVICE)
    assert entries == (
        {
            "fingerprint": item.fingerprint(),
            "rule_id": "L1-001",
            "object_key": "firewall policy/1",
            "accepted_at": "2026-09-12T05:00:00Z",
            "accepted_by": ACCEPTED_BY,
            "note": NOTE,
            "run_id": run_id,
        },
    )


def test_accept_baseline_is_idempotent_over_the_same_run():
    with Store(":memory:") as store:
        run_id = record(store, trio())
        assert accept(store, run_id, accepted_at="2026-09-01T05:00:00Z") == 3
        first = store.baseline_entries(TENANT, DEVICE)
        assert accept(store, run_id, accepted_at="2026-09-11T05:00:00Z") == 0
        assert accept(store, run_id, accepted_by="nekdo jiny", note="jiny duvod") == 0
        assert baseline_count(store) == 3
        assert store.baseline_entries(TENANT, DEVICE) == first


def test_accept_baseline_of_a_later_run_adds_only_the_new_findings():
    with Store(":memory:") as store:
        first_run = record(store, trio(), started_at="2026-09-01T05:00:00Z")
        assert accept(store, first_run) == 3
        later = trio() + (make_finding(rule_id="L1-003", object_key="firewall policy/4"),)
        second_run = record(store, later, started_at="2026-09-11T05:00:00Z")
        assert accept(store, second_run) == 1
        assert baseline_count(store) == 4
        assert len(store.baseline_fingerprints(TENANT, DEVICE)) == 4


def test_accept_baseline_refuses_a_run_of_another_tenant():
    with Store(":memory:") as store:
        mine = record(store, trio(), tenant="tenant-a")
        with pytest.raises(StoreError):
            accept(store, mine, tenant="tenant-b")
        assert baseline_count(store) == 0
        assert store.baseline_fingerprints("tenant-b", DEVICE) == frozenset()
        assert accept(store, mine, tenant="tenant-a") == 3
        assert store.baseline_fingerprints("tenant-b", DEVICE) == frozenset()
        assert store.baseline_entries("tenant-b", DEVICE) == ()
        assert len(store.baseline_fingerprints("tenant-a", DEVICE)) == 3


def test_baseline_is_scoped_to_the_tenant_and_the_device():
    ours = make_finding(tenant="tenant-a")
    theirs = make_finding(tenant="tenant-b")
    assert ours.fingerprint() != theirs.fingerprint()
    with Store(":memory:") as store:
        mine = record(store, (ours,), tenant="tenant-a")
        other = record(store, (theirs,), tenant="tenant-b")
        assert accept(store, mine, tenant="tenant-a") == 1
        assert accept(store, other, tenant="tenant-b") == 1
        assert store.baseline_fingerprints("tenant-a", DEVICE) == frozenset((ours.fingerprint(),))
        assert store.baseline_fingerprints("tenant-b", DEVICE) == frozenset((theirs.fingerprint(),))
        assert store.baseline_fingerprints("tenant-c", DEVICE) == frozenset()
        assert store.baseline_fingerprints("tenant-a", "fw-z.example.invalid") == frozenset()
        assert store.baseline_entries("tenant-c", DEVICE) == ()
        assert store.baseline_entries("tenant-a", "fw-z.example.invalid") == ()


def test_accept_baseline_refuses_a_run_of_another_device():
    with Store(":memory:") as store:
        run_id = record(store, (make_finding(),))
        with pytest.raises(StoreError):
            accept(store, run_id, device="fw-b.example.invalid")
        assert baseline_count(store) == 0
        assert store.baseline_fingerprints("fw-b.example.invalid", DEVICE) == frozenset()


@pytest.mark.parametrize("missing", (4242, 0, -1, None))
def test_accept_baseline_over_an_unknown_run_is_refused(missing):
    with Store(":memory:") as store:
        run_id = record(store, (make_finding(),))
        with pytest.raises(StoreError):
            accept(store, missing)
        assert baseline_count(store) == 0
        assert accept(store, run_id) == 1


@pytest.mark.parametrize("field", ("accepted_by", "note", "tenant", "device"))
@pytest.mark.parametrize("value", ("", "   ", "\t\n", None))
def test_accept_baseline_without_owner_reason_or_scope_is_refused(field, value):
    with Store(":memory:") as store:
        run_id = record(store, trio())
        with pytest.raises(StoreError):
            accept(store, run_id, **{field: value})
        assert baseline_count(store) == 0
        assert store.baseline_fingerprints(TENANT, DEVICE) == frozenset()
        assert accept(store, run_id) == 3


@pytest.mark.parametrize(
    "moment",
    (
        "vcera",
        "",
        "2026-09-12",
        "2026-09-12T05:00:00",
        "2026-09-12T05:00:00+00:00",
        "2026-09-12T05:00:00.123456Z",
        "2026-9-1T5:00:00Z",
        "9999",
        20260912,
    ),
)
def test_accepted_at_must_be_iso_utc_with_zulu_suffix(moment):
    with Store(":memory:") as store:
        run_id = record(store, trio())
        with pytest.raises(StoreError):
            accept(store, run_id, accepted_at=moment)
        assert baseline_count(store) == 0
        assert accept(store, run_id, accepted_at="2026-09-12T05:00:00Z") == 3


def test_accepted_at_defaults_to_utc_with_zulu_suffix():
    with Store(":memory:") as store:
        run_id = record(store, (make_finding(),))
        accept(store, run_id)
        moment = store.baseline_entries(TENANT, DEVICE)[0]["accepted_at"]
    assert moment.endswith("Z")
    assert datetime.strptime(moment, "%Y-%m-%dT%H:%M:%SZ").year >= 2026


def test_baseline_entries_order_is_deterministic():
    items = (
        make_finding(rule_id="L1-002", object_key="firewall policy/9"),
        make_finding(rule_id="L1-001", object_key="firewall policy/9"),
        make_finding(rule_id="L1-002", object_key="firewall policy/1"),
        make_finding(rule_id="L1-001", object_key="firewall policy/1"),
    )
    with Store(":memory:") as store:
        run_id = record(store, items)
        accept(store, run_id)
        first = tuple((entry["rule_id"], entry["object_key"]) for entry in store.baseline_entries(TENANT, DEVICE))
        second = tuple((entry["rule_id"], entry["object_key"]) for entry in store.baseline_entries(TENANT, DEVICE))
    assert first == (
        ("L1-001", "firewall policy/1"),
        ("L1-001", "firewall policy/9"),
        ("L1-002", "firewall policy/1"),
        ("L1-002", "firewall policy/9"),
    )
    assert first == second


def test_failed_baseline_write_accepts_nothing():
    with Store(":memory:") as store:
        run_id = record(store, trio())
        real = store._connection
        store._connection = FlakyConnection(real, 2)
        with pytest.raises(RuntimeError):
            accept(store, run_id)
        store._connection = real
        assert baseline_count(store) == 0
        assert store.baseline_fingerprints(TENANT, DEVICE) == frozenset()
        assert accept(store, run_id) == 3
        assert baseline_count(store) == 3


def test_accept_baseline_over_a_run_without_findings_accepts_nothing():
    with Store(":memory:") as store:
        run_id = record(store)
        assert accept(store, run_id) == 0
        assert baseline_count(store) == 0
        assert store.baseline_entries(TENANT, DEVICE) == ()


def test_accepted_baseline_survives_reopen(tmp_path):
    path = tmp_path / "audit.db"
    with Store(path) as store:
        run_id = record(store, trio())
        assert accept(store, run_id, accepted_at="2026-09-12T05:00:00Z") == 3
        expected = store.baseline_entries(TENANT, DEVICE)
    with Store(path) as store:
        assert store.baseline_entries(TENANT, DEVICE) == expected
        assert len(store.baseline_fingerprints(TENANT, DEVICE)) == 3
        assert accept(store, run_id) == 0


def test_forget_baseline_removes_one_entry_and_reports_it():
    items = trio()
    with Store(":memory:") as store:
        run_id = record(store, items)
        accept(store, run_id)
        target = items[0].fingerprint()
        assert store.forget_baseline(TENANT, DEVICE, target) is True
        assert target not in store.baseline_fingerprints(TENANT, DEVICE)
        assert baseline_count(store) == 2
        assert store.forget_baseline(TENANT, DEVICE, target) is False
        assert store.forget_baseline(TENANT, DEVICE, "0" * 64) is False
        assert baseline_count(store) == 2
        assert accept(store, run_id) == 1


def test_forget_baseline_cannot_reach_another_tenant_or_device():
    item = make_finding()
    with Store(":memory:") as store:
        mine = record(store, (item,), tenant="tenant-a")
        accept(store, mine, tenant="tenant-a")
        assert store.forget_baseline("tenant-b", DEVICE, item.fingerprint()) is False
        assert store.forget_baseline("tenant-a", "fw-z.example.invalid", item.fingerprint()) is False
        assert store.baseline_fingerprints("tenant-a", DEVICE) == frozenset((item.fingerprint(),))
        assert store.forget_baseline("tenant-a", DEVICE, item.fingerprint()) is True
        assert store.baseline_fingerprints("tenant-a", DEVICE) == frozenset()


@pytest.mark.parametrize("field", ("tenant", "device", "fingerprint"))
@pytest.mark.parametrize("value", ("", "   ", None))
def test_forget_baseline_without_scope_is_refused(field, value):
    item = make_finding()
    arguments = {"tenant": TENANT, "device": DEVICE, "fingerprint": item.fingerprint()}
    arguments[field] = value
    with Store(":memory:") as store:
        run_id = record(store, (item,))
        accept(store, run_id)
        with pytest.raises(StoreError):
            store.forget_baseline(arguments["tenant"], arguments["device"], arguments["fingerprint"])
        assert baseline_count(store) == 1


CANARY = "KANARCI-RETEZEC-NESMI-UNIKNOUT"

CHANNEL_EVENT_SCHEMA = (
    "id",
    "tenant",
    "device",
    "run_id",
    "channel",
    "request",
    "response_sha256",
    "response_bytes",
    "started_at",
    "finished_at",
    "outcome",
)

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

REQUEST = "ssh show full-configuration"
DIGEST = "b" * 64

INSERT_CHANNEL_EVENT = (
    "INSERT INTO channel_events"
    " (tenant, device, run_id, channel, request, response_sha256, response_bytes,"
    " started_at, finished_at, outcome)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def event(**overrides):
    fields = {
        "device": DEVICE,
        "channel": "ssh",
        "request": REQUEST,
        "response_sha256": DIGEST,
        "response_bytes": 4096,
        "started_at": "2026-09-12T05:00:00Z",
        "finished_at": "2026-09-12T05:00:02Z",
        "outcome": "ok",
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


class FlakyChannelConnection:
    def __init__(self, connection, fail_on):
        self._connection = connection
        self._fail_on = fail_on
        self._writes = 0

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def execute(self, statement, *args):
        if "INTO channel_events" in statement:
            self._writes += 1
            if self._writes == self._fail_on:
                raise RuntimeError("zapis selhal")
        return self._connection.execute(statement, *args)


def channel_event_count(store):
    return store._connection.execute("SELECT count(*) FROM channel_events").fetchone()[0]


def whole_channel_events_table(store):
    rows = store._connection.execute("SELECT * FROM channel_events").fetchall()
    return "\n".join("\n".join(repr(value) for value in tuple(row)) for row in rows)


def whole_database(store):
    return "\n".join(store._connection.iterdump())


def test_channel_events_schema_has_its_columns_and_both_indexes():
    with Store(":memory:") as store:
        assert columns(store, "channel_events") == CHANNEL_EVENT_SCHEMA
        indexes = store._connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'channel_events' ORDER BY name"
        ).fetchall()
        assert tuple(row["name"] for row in indexes) == ("channel_events_run_id", "channel_events_tenant_device")


def test_channel_events_run_id_is_the_only_nullable_column():
    with Store(":memory:") as store:
        rows = store._connection.execute("PRAGMA table_info(channel_events)").fetchall()
        nullable = tuple(row["name"] for row in rows if not row["notnull"])
    assert nullable == ("id", "run_id")


def test_channel_event_round_trips_with_its_run():
    with Store(":memory:") as store:
        run_id = record(store)
        assert store.record_channel_events(TENANT, DEVICE, (event(),), run_id=run_id) == 1
        stored = store.channel_events(TENANT, DEVICE)
    assert len(stored) == 1
    assert stored[0] == {
        "id": stored[0]["id"],
        "tenant": TENANT,
        "device": DEVICE,
        "run_id": run_id,
        "channel": "ssh",
        "request": REQUEST,
        "response_sha256": DIGEST,
        "response_bytes": 4096,
        "started_at": "2026-09-12T05:00:00Z",
        "finished_at": "2026-09-12T05:00:02Z",
        "outcome": "ok",
    }


def test_channel_event_body_never_reaches_the_store():
    smuggled = event(
        text=CANARY,
        body=CANARY,
        response=CANARY,
        configuration=CANARY.encode(),
        evidence={"config": CANARY},
    )
    assert smuggled.text == CANARY
    with Store(":memory:") as store:
        run_id = record(store)
        assert store.record_channel_events(TENANT, DEVICE, (smuggled,), run_id=run_id) == 1
        table = whole_channel_events_table(store)
        database = whole_database(store)
        stored = store.channel_events(TENANT, DEVICE)
    assert CANARY not in table
    assert CANARY not in database
    assert CANARY not in repr(stored)
    assert tuple(sorted(stored[0])) == tuple(sorted(CHANNEL_EVENT_SCHEMA))
    assert DIGEST in table


def test_channel_event_of_a_failed_collection_is_kept_without_a_run():
    failed = event(
        outcome="failed",
        response_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        response_bytes=0,
        started_at="2026-09-12T05:00:00Z",
        finished_at="2026-09-12T05:02:00Z",
    )
    taken = event(started_at="2026-09-12T06:00:00Z", finished_at="2026-09-12T06:00:03Z")
    with Store(":memory:") as store:
        assert store.record_channel_events(TENANT, DEVICE, (failed,)) == 1
        assert store.runs_for_device(TENANT, DEVICE) == ()
        run_id = record(store, (make_finding(),), started_at="2026-09-12T06:00:00Z")
        assert store.record_channel_events(TENANT, DEVICE, (taken,), run_id=run_id) == 1
        trace = store.channel_events(TENANT, DEVICE)
        for_run = store.channel_events_for_run(TENANT, run_id)
    assert tuple((item["outcome"], item["run_id"]) for item in trace) == (("ok", run_id), ("failed", None))
    assert tuple(item["outcome"] for item in for_run) == ("ok",)


def test_channel_events_without_a_run_are_not_read_as_a_run():
    with Store(":memory:") as store:
        store.record_channel_events(TENANT, DEVICE, (event(outcome="failed"),))
        run_id = record(store)
        assert store.channel_events_for_run(TENANT, run_id) == ()
        assert store.channel_events_for_run(TENANT, None) == ()
        assert len(store.channel_events(TENANT, DEVICE)) == 1


def test_channel_events_survive_reopen(tmp_path):
    path = tmp_path / "audit.db"
    with Store(path) as store:
        store.record_channel_events(TENANT, DEVICE, (event(outcome="failed"),))
        expected = store.channel_events(TENANT, DEVICE)
    with Store(path) as store:
        assert store.channel_events(TENANT, DEVICE) == expected


def test_channel_events_are_scoped_to_the_tenant_on_the_same_device_name():
    with Store(":memory:") as store:
        store.record_channel_events("tenant-a", DEVICE, (event(request="mine"),))
        store.record_channel_events("tenant-b", DEVICE, (event(request="theirs"),))
        mine = store.channel_events("tenant-a", DEVICE)
        theirs = store.channel_events("tenant-b", DEVICE)
    assert tuple(item["request"] for item in mine) == ("mine",)
    assert tuple(item["request"] for item in theirs) == ("theirs",)


def test_channel_events_are_scoped_to_the_device():
    with Store(":memory:") as store:
        store.record_channel_events(TENANT, DEVICE, (event(),))
        assert store.channel_events(TENANT, "fw-b.example.invalid") == ()
        assert len(store.channel_events(TENANT, DEVICE)) == 1


def test_channel_events_for_run_is_scoped_to_the_tenant():
    with Store(":memory:") as store:
        mine = record(store, tenant="tenant-a")
        theirs = record(store, tenant="tenant-b")
        store.record_channel_events("tenant-a", DEVICE, (event(),), run_id=mine)
        store.record_channel_events("tenant-b", DEVICE, (event(),), run_id=theirs)
        assert len(store.channel_events_for_run("tenant-a", mine)) == 1
        assert store.channel_events_for_run("tenant-b", mine) == ()
        assert store.channel_events_for_run("tenant-a", theirs) == ()
        assert len(store.channel_events_for_run("tenant-b", theirs)) == 1


def test_record_channel_events_refuses_a_run_of_another_tenant():
    with Store(":memory:") as store:
        theirs = record(store, tenant="tenant-b")
        with pytest.raises(StoreError):
            store.record_channel_events("tenant-a", DEVICE, (event(),), run_id=theirs)
        assert channel_event_count(store) == 0
        assert store.channel_events("tenant-a", DEVICE) == ()


def test_record_channel_events_refuses_a_run_of_another_device():
    with Store(":memory:") as store:
        elsewhere = record(store, device="fw-b.example.invalid")
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, (event(),), run_id=elsewhere)
        assert channel_event_count(store) == 0


def test_record_channel_events_refuses_an_unknown_run():
    with Store(":memory:") as store:
        record(store)
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, (event(),), run_id=4242)
        assert channel_event_count(store) == 0


def test_channel_event_about_another_device_is_refused_and_rolled_back():
    stray = event(device="fw-b.example.invalid", request="stray")
    with Store(":memory:") as store:
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, (event(), stray, event()))
        assert channel_event_count(store) == 0
        assert store.record_channel_events(TENANT, DEVICE, (event(),)) == 1


def test_failed_channel_event_write_records_nothing():
    batch = (event(request="first"), event(request="second"), event(request="third"))
    with Store(":memory:") as store:
        real = store._connection
        store._connection = FlakyChannelConnection(real, 2)
        with pytest.raises(RuntimeError):
            store.record_channel_events(TENANT, DEVICE, batch)
        store._connection = real
        assert channel_event_count(store) == 0
        assert store.channel_events(TENANT, DEVICE) == ()
        assert store.record_channel_events(TENANT, DEVICE, batch) == 3
        assert channel_event_count(store) == 3


def test_one_broken_event_in_the_middle_writes_none_of_the_batch():
    batch = (event(request="first"), event(request="second", outcome="timeout"), event(request="third"))
    with Store(":memory:") as store:
        run_id = record(store)
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, batch, run_id=run_id)
        assert channel_event_count(store) == 0
        assert store.channel_events_for_run(TENANT, run_id) == ()


def test_empty_batch_writes_nothing_and_reports_it():
    with Store(":memory:") as store:
        run_id = record(store)
        assert store.record_channel_events(TENANT, DEVICE, (), run_id=run_id) == 0
        assert channel_event_count(store) == 0
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, (), run_id=run_id + 1000)


@pytest.mark.parametrize("field", ("device", "channel", "request", "response_sha256"))
@pytest.mark.parametrize("value", ("", "   ", "\t\n", None, 42))
def test_channel_event_without_a_mandatory_text_is_refused(field, value):
    with Store(":memory:") as store:
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, (event(**{field: value}),))
        assert channel_event_count(store) == 0


@pytest.mark.parametrize("field", CHANNEL_EVENT_FIELDS)
def test_channel_event_missing_a_field_entirely_is_refused(field):
    item = event()
    delattr(item, field)
    with Store(":memory:") as store:
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, (item,))
        assert channel_event_count(store) == 0


@pytest.mark.parametrize("field", ("started_at", "finished_at"))
@pytest.mark.parametrize(
    "moment",
    (
        "vcera",
        "",
        "2026-09-12",
        "2026-09-12T05:00:00",
        "2026-09-12T05:00:00+00:00",
        "2026-09-12T05:00:00.123456Z",
        "2026-9-1T5:00:00Z",
        None,
        20260912,
    ),
)
def test_channel_event_moments_must_be_iso_utc_with_zulu_suffix(field, moment):
    with Store(":memory:") as store:
        assert store.record_channel_events(TENANT, DEVICE, (event(),)) == 1
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, (event(**{field: moment}),))
        assert channel_event_count(store) == 1


@pytest.mark.parametrize("outcome", ("timeout", "OK", "ok ", "", None, True, 1, "failed  "))
def test_channel_event_outcome_is_only_ok_or_failed(outcome):
    with Store(":memory:") as store:
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, (event(outcome=outcome),))
        assert channel_event_count(store) == 0


@pytest.mark.parametrize("outcome", ("ok", "failed"))
def test_channel_event_outcome_accepts_both_verdicts(outcome):
    with Store(":memory:") as store:
        assert store.record_channel_events(TENANT, DEVICE, (event(outcome=outcome),)) == 1
        assert store.channel_events(TENANT, DEVICE)[0]["outcome"] == outcome


@pytest.mark.parametrize("size", (-1, True, False, "4096", 4096.0, None, object()))
def test_response_bytes_must_be_a_non_negative_whole_number(size):
    with Store(":memory:") as store:
        with pytest.raises(StoreError):
            store.record_channel_events(TENANT, DEVICE, (event(response_bytes=size),))
        assert channel_event_count(store) == 0


def test_response_bytes_may_be_zero():
    with Store(":memory:") as store:
        assert store.record_channel_events(TENANT, DEVICE, (event(response_bytes=0),)) == 1
        assert store.channel_events(TENANT, DEVICE)[0]["response_bytes"] == 0


@pytest.mark.parametrize("field", ("tenant", "device"))
@pytest.mark.parametrize("value", ("", "   ", "\t\n", None))
def test_record_channel_events_without_scope_is_refused(field, value):
    arguments = {"tenant": TENANT, "device": DEVICE}
    arguments[field] = value
    with Store(":memory:") as store:
        with pytest.raises(StoreError):
            store.record_channel_events(arguments["tenant"], arguments["device"], (event(),))
        assert channel_event_count(store) == 0


def test_channel_events_order_is_newest_first_and_deterministic():
    batch = (
        event(request="first", started_at="2026-09-12T05:00:00Z"),
        event(request="second", started_at="2026-09-12T07:00:00Z"),
        event(request="third", started_at="2026-09-12T06:00:00Z"),
        event(request="fourth", started_at="2026-09-12T07:00:00Z"),
    )
    with Store(":memory:") as store:
        store.record_channel_events(TENANT, DEVICE, batch)
        first = tuple(item["request"] for item in store.channel_events(TENANT, DEVICE))
        second = tuple(item["request"] for item in store.channel_events(TENANT, DEVICE))
    assert first == ("fourth", "second", "third", "first")
    assert first == second


def test_channel_events_for_run_reads_the_trace_in_the_order_it_happened():
    batch = (
        event(request="first", started_at="2026-09-12T05:00:02Z"),
        event(request="second", started_at="2026-09-12T05:00:01Z"),
        event(request="third", started_at="2026-09-12T05:00:03Z"),
    )
    with Store(":memory:") as store:
        run_id = record(store)
        store.record_channel_events(TENANT, DEVICE, batch, run_id=run_id)
        first = tuple(item["request"] for item in store.channel_events_for_run(TENANT, run_id))
        second = tuple(item["request"] for item in store.channel_events_for_run(TENANT, run_id))
    assert first == ("first", "second", "third")
    assert first == second


def test_channel_events_limit_takes_the_newest():
    batch = (
        event(request="first", started_at="2026-09-12T05:00:00Z"),
        event(request="second", started_at="2026-09-12T06:00:00Z"),
        event(request="third", started_at="2026-09-12T07:00:00Z"),
    )
    with Store(":memory:") as store:
        store.record_channel_events(TENANT, DEVICE, batch)
        assert tuple(item["request"] for item in store.channel_events(TENANT, DEVICE, limit=2)) == ("third", "second")
        assert store.channel_events(TENANT, DEVICE, limit=0) == ()
        assert len(store.channel_events(TENANT, DEVICE, limit=99)) == 3
        assert len(store.channel_events(TENANT, DEVICE)) == 3


@pytest.mark.parametrize("limit", (-1, True, "2", 2.0))
def test_channel_events_limit_must_be_a_non_negative_whole_number(limit):
    with Store(":memory:") as store:
        store.record_channel_events(TENANT, DEVICE, (event(),))
        with pytest.raises(StoreError):
            store.channel_events(TENANT, DEVICE, limit=limit)


def test_channel_events_run_id_is_a_foreign_key():
    with Store(":memory:") as store:
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                INSERT_CHANNEL_EVENT,
                (TENANT, DEVICE, 4242, "ssh", REQUEST, DIGEST, 4096, "2026-09-12T05:00:00Z", "2026-09-12T05:00:02Z", "ok"),
            )
        store._connection.execute(
            INSERT_CHANNEL_EVENT,
            (TENANT, DEVICE, None, "ssh", REQUEST, DIGEST, 4096, "2026-09-12T05:00:00Z", "2026-09-12T05:00:02Z", "ok"),
        )
        assert channel_event_count(store) == 1


OTHER_TENANT = "tenant-b"


def downgraded(path):
    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    for row in connection.execute(
        "SELECT id, rule_id, rule_version, device, object_key FROM findings"
    ).fetchall():
        connection.execute(
            "UPDATE findings SET fingerprint = ? WHERE id = ?",
            (fingerprint_v1(row["rule_id"], row["rule_version"], row["device"], row["object_key"]), row["id"]),
        )
    for row in connection.execute("SELECT id, rule_id, object_key, device FROM baseline").fetchall():
        connection.execute(
            "UPDATE baseline SET fingerprint = ? WHERE id = ?",
            (fingerprint_v1(row["rule_id"], 1, row["device"], row["object_key"]), row["id"]),
        )
    connection.execute("PRAGMA user_version = 0")
    connection.close()
    return path


def version_one_store(tmp_path, name="v1.sqlite3"):
    path = tmp_path / name
    with Store(path) as store:
        for tenant in (TENANT, OTHER_TENANT):
            item = make_finding(tenant=tenant)
            second = make_finding(rule_id="L1-002", object_key="firewall policy/2", tenant=tenant)
            run_id = record(store, (item, second), tenant=tenant)
            store.accept_baseline(tenant, DEVICE, run_id, "radek", "prevzato")
    return downgraded(path)


def fingerprints(path, table):
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    rows = connection.execute("SELECT tenant, fingerprint FROM %s" % table).fetchall() if table == "baseline" else connection.execute(
        "SELECT runs.tenant AS tenant, findings.fingerprint AS fingerprint FROM findings"
        " JOIN runs ON runs.id = findings.run_id ORDER BY findings.id"
    ).fetchall()
    connection.close()
    return tuple((row["tenant"], row["fingerprint"]) for row in rows)


def test_a_fresh_store_carries_the_schema_version(tmp_path):
    path = tmp_path / "audit.sqlite3"
    with Store(path) as store:
        assert schema_version(store._connection) == SCHEMA_VERSION
    connection = sqlite3.connect(str(path))
    assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    connection.close()


def test_opening_a_version_1_store_is_refused_and_names_the_migration(tmp_path):
    path = version_one_store(tmp_path)
    before = fingerprints(path, "findings")
    with pytest.raises(StoreError) as caught:
        Store(path)
    assert "schema version %d" % PREVIOUS_SCHEMA_VERSION in str(caught.value)
    assert MIGRATE_COMMAND in str(caught.value)
    assert fingerprints(path, "findings") == before


def test_migration_recomputes_every_fingerprint_from_the_tenant_of_its_run(tmp_path):
    path = version_one_store(tmp_path)
    before = fingerprints(path, "findings")
    assert len({fingerprint for _, fingerprint in before}) == 2
    counts = migrate(path)
    assert counts == {"findings": 4, "baseline": 4}
    after = fingerprints(path, "findings")
    assert len(after) == len(before) == 4
    assert len({fingerprint for _, fingerprint in after}) == 4
    for tenant, fingerprint in after:
        assert fingerprint in (
            fingerprint_of("L1-001", 1, tenant, DEVICE, "firewall policy/1"),
            fingerprint_of("L1-002", 1, tenant, DEVICE, "firewall policy/2"),
        )


def test_migration_keeps_the_baseline_pointing_at_the_same_findings(tmp_path):
    path = version_one_store(tmp_path)
    migrate(path)
    with Store(path) as store:
        for tenant in (TENANT, OTHER_TENANT):
            run = store.last_run(tenant, DEVICE)
            stored = store.findings_for_run(tenant, run["id"])
            assert len(stored) == 2
            assert store.baseline_fingerprints(tenant, DEVICE) == frozenset(
                item["fingerprint"] for item in stored
            )
        assert store.baseline_fingerprints(TENANT, DEVICE) != store.baseline_fingerprints(
            OTHER_TENANT, DEVICE
        )


def test_migration_is_an_explicit_step_that_runs_once(tmp_path):
    path = version_one_store(tmp_path)
    migrate(path)
    with pytest.raises(StoreError, match="already holds schema version"):
        migrate(path)
    with Store(path) as store:
        assert schema_version(store._connection) == SCHEMA_VERSION


def stored_fingerprints(path):
    connection = sqlite3.connect(str(path))
    rows = connection.execute("SELECT fingerprint FROM findings ORDER BY id").fetchall()
    connection.close()
    return tuple(row[0] for row in rows)


def test_migration_refuses_a_finding_whose_run_names_no_tenant(tmp_path):
    path = version_one_store(tmp_path)
    before = stored_fingerprints(path)
    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.execute("UPDATE findings SET run_id = 9999 WHERE id = 1")
    connection.close()
    with pytest.raises(StoreError, match="belongs to no run that names a tenant"):
        migrate(path)
    connection = sqlite3.connect(str(path))
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    connection.close()
    assert stored_fingerprints(path) == before


def test_migration_needs_a_store_that_holds_the_schema(tmp_path):
    empty = tmp_path / "empty.sqlite3"
    empty.touch()
    with pytest.raises(StoreError, match="holds no audit schema"):
        migrate(empty)
