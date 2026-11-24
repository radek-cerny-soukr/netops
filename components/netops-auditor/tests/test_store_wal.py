"""The store in WAL: no copy of the store per MCP call, read-only reader, switch of an older store (verification).

The suite runs in the hardened test container (read-only root file system, the store under the
writable /pytmp, UID 51000), so the reader tests here show the read-only reader (mode=ro) in that
setting: it reads the WAL store, creates the -wal/-shm files beside it in the writable store
directory when the writer has removed them, and a concurrent COMMIT passes.
"""
import os
import sqlite3
import stat
import threading
import time
import tracemalloc
from types import SimpleNamespace

import pytest

pytest.importorskip("fastmcp")

from netops_auditor import mcp_server
from netops_auditor import store as store_module
from netops_auditor.findings import Finding
from netops_auditor.mcp_server import ReadOnlyStore
from netops_auditor.store import SCHEMA_VERSION, Store
from test_mcp_server import (  # noqa: F401  (fixtures)
    DEVICE,
    RULES_VERSION,
    TENANT,
    _finding,
    audited,
    clean_configuration,
)

WAIT_SECONDS = 0.5
BULK_DEVICE = "fw-bulk.example.invalid"
BULK_RUNS = 50
BULK_FINDINGS = 50
BULK_EVIDENCE_CHARS = 4000
MIN_STORE_BYTES = 8 * 1024 * 1024
# Python memory of three MCP calls over one small device; independent of the size of the store.
MAX_CALL_BYTES = 1024 * 1024


@pytest.fixture
def short_busy_timeout(monkeypatch):
    monkeypatch.setattr(store_module, "BUSY_TIMEOUT_SECONDS", WAIT_SECONDS)
    monkeypatch.setattr(mcp_server, "BUSY_TIMEOUT_SECONDS", WAIT_SECONDS)


def _side_files(path):
    return tuple(path.with_name(path.name + suffix) for suffix in ("-wal", "-shm"))


def _header_versions(path):
    # Bytes 18 and 19 of the SQLite header: 1 = rollback journal, 2 = WAL.
    with open(path, "rb") as stream:
        header = stream.read(20)
    return header[18], header[19]


def _journal_mode(path):
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        return connection.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        connection.close()


def _dump(path):
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        return tuple(connection.iterdump()), connection.execute("PRAGMA user_version").fetchone()[0]
    finally:
        connection.close()


def _to_rollback_journal(path):
    """Turn a store back into the rollback journal of releases up to 1.0.9."""
    connection = sqlite3.connect(str(path), isolation_level=None)
    try:
        assert connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0] == "delete"
    finally:
        connection.close()
    assert _header_versions(path) == (1, 1)


def _record(writer, sha):
    return writer.record_run(
        TENANT, DEVICE, sha, "history/%s.conf" % sha, RULES_VERSION,
        (_finding("L1-009", "firewall policy/3"),),
    )


def test_a_writer_keeps_the_store_in_wal_and_removes_the_wal_files_when_it_closes(tmp_path):
    path = tmp_path / "audit.db"
    with Store(path) as store:
        assert store._connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        _record(store, "sha-one")
    assert _header_versions(path) == (2, 2)
    assert [item.exists() for item in _side_files(path)] == [False, False]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_an_older_rollback_journal_store_is_switched_once_without_data_loss(audited):
    path = audited.path
    _to_rollback_journal(path)
    before = _dump(path)
    # The read-only reader reads the older store as it is and never switches it.
    with ReadOnlyStore(path) as reader:
        assert reader.last_run(TENANT, DEVICE)["id"] == audited.second_run
    assert _header_versions(path) == (1, 1)
    assert _dump(path) == before
    with Store(path) as writer:
        assert writer._connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert writer.last_run(TENANT, DEVICE)["id"] == audited.second_run
        assert len(writer.baseline_entries(TENANT, DEVICE)) == 2
    assert _header_versions(path) == (2, 2)
    assert _journal_mode(path) == "wal"
    assert _dump(path) == before
    with Store(path):
        pass
    assert _dump(path) == before


def test_a_nonempty_v2_rollback_journal_store_of_two_tenants_is_switched_to_wal_without_data_loss(tmp_path):
    path = tmp_path / "older.sqlite3"
    with Store(path) as store:
        for tenant in (TENANT, "tenant-b"):
            run_id = store.record_run(
                tenant, DEVICE, "sha-" + tenant, "history/%s.conf" % tenant, RULES_VERSION,
                (_finding("L1-001", "firewall policy/1", tenant=tenant),
                 _finding("L1-002", "firewall policy/2", tenant=tenant)),
            )
            store.accept_baseline(tenant, DEVICE, run_id, "operator", "prevzato")
    _to_rollback_journal(path)
    older = _dump(path)
    assert older[1] == SCHEMA_VERSION
    with Store(path) as store:
        assert store._connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        for tenant in (TENANT, "tenant-b"):
            assert len(store.baseline_entries(tenant, DEVICE)) == 2
    assert _dump(path) == older
    assert _header_versions(path) == (2, 2)


def test_the_switch_to_wal_waits_for_another_writer_without_data_loss(audited, monkeypatch):
    path = audited.path
    _to_rollback_journal(path)
    before = _dump(path)
    holder = sqlite3.connect(str(path), isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    waits = []

    def release(seconds):
        waits.append(seconds)
        holder.execute("ROLLBACK")
        holder.close()

    monkeypatch.setattr(store_module, "time", SimpleNamespace(monotonic=time.monotonic, sleep=release))
    try:
        with Store(path) as writer:
            assert writer._connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    finally:
        holder.close()
    assert waits == [store_module._RETRY_SECONDS]
    assert _header_versions(path) == (2, 2)
    assert _dump(path) == before


def test_the_read_only_reader_reads_the_wal_store_and_a_concurrent_commit_passes(audited, short_busy_timeout):
    path = audited.path
    assert [item.exists() for item in _side_files(path)] == [False, False]
    assert os.access(path.parent, os.W_OK)
    with ReadOnlyStore(path) as reader:
        assert reader._connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        previous = reader.last_run(TENANT, DEVICE)
        assert previous["id"] == audited.second_run
        # The reader (mode=ro) has created the WAL files beside the store with its mode.
        for item in _side_files(path):
            assert item.exists()
            assert stat.S_IMODE(item.stat().st_mode) == 0o600
        assert reader._connection.in_transaction
        with Store(path) as writer:
            run_id = _record(writer, "sha-third")
        # The COMMIT passed while the reader held its read transaction; the reader keeps its state.
        assert reader._connection.in_transaction
        assert reader.last_run(TENANT, DEVICE) == previous
        with pytest.raises(sqlite3.OperationalError):
            reader._connection.execute("DELETE FROM findings")
    with ReadOnlyStore(path) as reader:
        assert reader.last_run(TENANT, DEVICE)["id"] == run_id
        assert reader.last_run("tenant-other", DEVICE) is None


def test_a_reader_in_one_thread_and_a_writer_in_another_both_finish(audited, short_busy_timeout):
    path = audited.path
    opened, committed, outcome = threading.Event(), threading.Event(), {}

    def read():
        try:
            with ReadOnlyStore(path) as reader:
                outcome["before"] = reader.last_run(TENANT, DEVICE)["id"]
                opened.set()
                committed.wait(30)
                outcome["after"] = reader.last_run(TENANT, DEVICE)["id"]
        except Exception as error:
            outcome["error"] = repr(error)
            opened.set()

    thread = threading.Thread(target=read, name="mcp-reader")
    thread.start()
    try:
        assert opened.wait(30)
        with Store(path) as writer:
            run_id = _record(writer, "sha-third")
    finally:
        committed.set()
        thread.join(30)
    assert outcome == {"before": audited.second_run, "after": audited.second_run}
    with ReadOnlyStore(path) as reader:
        assert reader.last_run(TENANT, DEVICE)["id"] == run_id


def _bulk_store(path):
    value = "x" * BULK_EVIDENCE_CHARS
    with Store(path) as store:
        for number in range(BULK_RUNS):
            findings = tuple(
                Finding(
                    rule_id="L1-001",
                    rule_version=1,
                    tenant=TENANT,
                    device=BULK_DEVICE,
                    object_key="firewall policy/%d" % item,
                    severity="high",
                    rule_class="fakt",
                    section="firewall policy",
                    line=12,
                    evidence=(("attribute", "comments"), ("value", value)),
                )
                for item in range(BULK_FINDINGS)
            )
            store.record_run(TENANT, BULK_DEVICE, "sha-bulk-%d" % number, "history/bulk.conf", RULES_VERSION, findings)
        store.record_run(
            TENANT, DEVICE, "sha-small", "history/small.conf", RULES_VERSION,
            (_finding("L1-001", "firewall policy/1"),),
        )


def test_an_mcp_call_does_not_copy_the_store(tmp_path, monkeypatch):
    path = tmp_path / "audit.db"
    _bulk_store(path)
    assert path.stat().st_size > MIN_STORE_BYTES
    copies = []
    real_connect = sqlite3.connect

    class Watched(sqlite3.Connection):
        def serialize(self, *args, **keywords):
            copies.append("serialize")
            return super().serialize(*args, **keywords)

        def deserialize(self, *args, **keywords):
            copies.append("deserialize")
            return super().deserialize(*args, **keywords)

    def connect(*args, **keywords):
        keywords.setdefault("factory", Watched)
        return real_connect(*args, **keywords)

    monkeypatch.setattr(sqlite3, "connect", connect)
    mcp_server.configure({
        mcp_server.STORE_VARIABLE: str(path),
        mcp_server.TENANT_VARIABLE: TENANT,
        mcp_server.CATALOG_VARIABLE: "fortios",
    })
    tracemalloc.start()
    try:
        status = mcp_server.audit_status(device=DEVICE)
        summary = mcp_server.findings_summary(device=DEVICE)
        listing = mcp_server.list_findings(DEVICE)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert copies == []
    assert status["devices"][0]["findings_total"] == 1
    assert summary["total_matching"] == 1
    assert listing["total"] == 1
    # tracemalloc sees Python objects (a serialized copy is one); the SQLite page cache is bounded on its own.
    assert peak < MAX_CALL_BYTES, peak
