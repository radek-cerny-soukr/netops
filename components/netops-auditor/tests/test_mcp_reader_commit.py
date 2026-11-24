"""A long read-only MCP call must not hold up the COMMIT of a concurrent collect (verification-B3).

Real SQLite concurrency on one store file: the MCP reader (ReadOnlyStore) and the Auditor
writer (Store.record_run) use their own connections; nothing mocks COMMIT. Only the busy
timeout is lowered through the existing constant, so that a blocked COMMIT fails quickly
(the RED of verification). No test asserts an absolute duration: the condition is that the
COMMIT finishes while the reader is still inside its tool call and still holds its read
transaction (verification: WAL, no copy of the store).
"""
import threading

import pytest

pytest.importorskip("fastmcp")

from netops_auditor import mcp_server, query
from netops_auditor import store as store_module
from netops_auditor.store import Store
from test_mcp_server import (  # noqa: F401  (fixtures)
    DEVICE,
    OTHER_DEVICE,
    RULES_VERSION,
    TENANT,
    _finding,
    audited,
    clean_configuration,
)

WAIT_SECONDS = 0.5


@pytest.fixture
def short_busy_timeout(monkeypatch):
    monkeypatch.setattr(store_module, "BUSY_TIMEOUT_SECONDS", WAIT_SECONDS)
    monkeypatch.setattr(mcp_server, "BUSY_TIMEOUT_SECONDS", WAIT_SECONDS)


def _configure(path):
    mcp_server.configure({
        mcp_server.STORE_VARIABLE: str(path),
        mcp_server.TENANT_VARIABLE: TENANT,
        mcp_server.CATALOG_VARIABLE: "fortios",
    })


def _paused_summary(monkeypatch):
    """Start findings_summary in a thread and hold it after the first device (slow Python part)."""
    paused, released, outcome = threading.Event(), threading.Event(), {}
    real = query._device_entries

    def slow(*args, **keywords):
        result = real(*args, **keywords)
        if not paused.is_set():
            connection = args[0]._connection
            outcome["held_before"] = connection.in_transaction
            paused.set()
            released.wait(30)
            outcome["held_after"] = connection.in_transaction
        return result

    monkeypatch.setattr(query, "_device_entries", slow)

    def read():
        try:
            outcome["read"] = mcp_server.findings_summary()
        except Exception as error:
            outcome["read"] = repr(error)

    thread = threading.Thread(target=read, name="mcp-reader")
    thread.start()
    assert paused.wait(30)
    return thread, released, outcome


def _record(writer, device, rule_id, object_key, sha):
    return writer.record_run(
        TENANT, device, sha, "history/%s.conf" % sha, RULES_VERSION,
        (_finding(rule_id, object_key, device=device),),
    )


def test_a_long_findings_summary_does_not_make_a_collect_commit_fail(audited, short_busy_timeout, monkeypatch):
    _configure(audited.path)
    thread, released, outcome = _paused_summary(monkeypatch)
    try:
        with Store(audited.path) as writer:
            run_id = _record(writer, DEVICE, "L1-009", "firewall policy/3", "sha-third")
        # The COMMIT has finished while the reader is still inside its tool call.
        assert thread.is_alive()
    finally:
        released.set()
        thread.join(30)
    # The reader held its read transaction (no copy of the store) before and after that COMMIT.
    assert (outcome["held_before"], outcome["held_after"]) == (True, True)
    assert isinstance(outcome["read"], dict), outcome["read"]
    with Store(audited.path) as store:
        assert store.last_run(TENANT, DEVICE)["id"] == run_id


def test_a_findings_summary_during_collect_returns_the_previous_or_the_new_state_never_a_mix(
    audited, short_busy_timeout, monkeypatch
):
    _configure(audited.path)
    before = mcp_server.findings_summary()
    thread, released, outcome = _paused_summary(monkeypatch)
    try:
        # The reader has classified the first device; both devices now get a new run.
        with Store(audited.path) as writer:
            _record(writer, DEVICE, "L1-009", "firewall policy/3", "sha-third")
            _record(writer, OTHER_DEVICE, "L1-009", "firewall policy/4", "sha-other-2")
    finally:
        released.set()
        thread.join(30)
    after = mcp_server.findings_summary()
    assert before != after
    assert {item["device"] for item in before["items"]} == {DEVICE, OTHER_DEVICE}
    assert {item["device"] for item in after["items"]} == {DEVICE, OTHER_DEVICE}
    assert outcome["read"] in (before, after)


def test_a_read_only_store_keeps_its_state_while_a_writer_commits(audited, short_busy_timeout):
    from netops_auditor.mcp_server import ReadOnlyStore

    with ReadOnlyStore(audited.path) as reader:
        previous = reader.last_run(TENANT, DEVICE)
        previous_findings = reader.findings_for_run(TENANT, previous["id"])
        with Store(audited.path) as writer:
            run_id = _record(writer, DEVICE, "L1-009", "firewall policy/3", "sha-third")
        assert reader.last_run(TENANT, DEVICE) == previous
        assert reader.findings_for_run(TENANT, previous["id"]) == previous_findings
        assert reader.runs_for_device(TENANT, DEVICE)[0]["id"] == previous["id"]
    with ReadOnlyStore(audited.path) as reader:
        assert reader.last_run(TENANT, DEVICE)["id"] == run_id
        assert reader.last_run("tenant-other", DEVICE) is None
