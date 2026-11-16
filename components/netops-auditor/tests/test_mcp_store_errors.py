import asyncio
import logging
import sqlite3

import pytest

pytest.importorskip("fastmcp")

from fastmcp.exceptions import ToolError

from netops_auditor import mcp_server
from test_cli import DEVICE, TENANT
from test_store_concurrency import LOCK_WAIT_SECONDS, _audited_store, _corrupt_table


@pytest.fixture(autouse=True)
def clean_configuration():
    mcp_server._CONFIGURATION = None
    yield
    mcp_server._CONFIGURATION = None


def _configure(database):
    mcp_server.configure({
        mcp_server.STORE_VARIABLE: str(database),
        mcp_server.TENANT_VARIABLE: TENANT,
        mcp_server.CATALOG_VARIABLE: "fortios",
    })


def test_a_corrupted_store_page_is_a_tool_error_with_a_store_message(tmp_path, capsys, caplog):
    database, _ = _audited_store(tmp_path, capsys)
    _configure(database)
    _corrupt_table(database, "findings")
    with pytest.raises(ToolError) as direct:
        mcp_server.list_findings(DEVICE)
    assert str(direct.value).startswith("store ")
    assert "malformed" in str(direct.value)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ToolError) as surfaced:
        asyncio.run(mcp_server.mcp.call_tool("list_findings", {"device": DEVICE}))
    assert str(surfaced.value) == str(direct.value)
    assert not [record for record in caplog.records if record.exc_info]


def test_a_locked_store_is_a_tool_error_with_a_store_message(tmp_path, capsys, monkeypatch):
    database, _ = _audited_store(tmp_path, capsys)
    _configure(database)
    real_connect = sqlite3.connect

    def connect(*args, **keywords):
        keywords["timeout"] = LOCK_WAIT_SECONDS
        return real_connect(*args, **keywords)

    monkeypatch.setattr(sqlite3, "connect", connect)
    holder = real_connect(str(database), isolation_level=None)
    # The store is in WAL, where BEGIN EXCLUSIVE does not keep readers out; a connection in
    # exclusive locking mode does (it holds the store file itself), as a stuck tool would.
    holder.execute("PRAGMA locking_mode = EXCLUSIVE")
    holder.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ToolError) as error:
            mcp_server.audit_status(DEVICE)
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert str(database) in str(error.value)
    assert "database is locked" in str(error.value)


@pytest.mark.parametrize("tool,arguments,message", [
    ("list_findings", {"device": DEVICE, "severity": "critical"}, "severity must be one of "),
    ("list_findings", {"device": DEVICE, "since": "yesterday"}, "since must be ISO 8601 UTC "),
    ("audit_status", {"stale_after_hours": -1.0}, "stale_after_hours must be a positive number"),
    ("rule_detail", {"rule_id": "no.such.rule"}, "the catalog holds no rule 'no.such.rule'"),
    ("compare", {"device": DEVICE, "first_run_id": 1, "second_run_id": 999}, "run 999 does not belong to tenant"),
])
def test_a_query_error_is_a_tool_error_with_its_own_message(tmp_path, capsys, caplog, tool, arguments, message):
    database, _ = _audited_store(tmp_path, capsys)
    _configure(database)
    with pytest.raises(ToolError) as direct:
        getattr(mcp_server, tool)(**arguments)
    assert str(direct.value).startswith(message)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ToolError) as surfaced:
        asyncio.run(mcp_server.mcp.call_tool(tool, arguments))
    assert str(surfaced.value) == str(direct.value)
    assert "Error calling tool" not in str(surfaced.value)
    assert not [record for record in caplog.records if record.exc_info]


def test_store_writer_and_mcp_reader_use_the_explicit_busy_timeout(tmp_path, capsys, monkeypatch):
    from netops_auditor.store import BUSY_TIMEOUT_SECONDS, Store
    database, _ = _audited_store(tmp_path, capsys)
    _configure(database)
    real_connect = sqlite3.connect
    timeouts = []

    def connect(*args, **keywords):
        timeouts.append(keywords.get("timeout"))
        return real_connect(*args, **keywords)

    monkeypatch.setattr(sqlite3, "connect", connect)
    Store(database).close()
    mcp_server.audit_status(DEVICE)
    assert BUSY_TIMEOUT_SECONDS == 15.0
    assert len(timeouts) >= 2
    assert all(timeout == BUSY_TIMEOUT_SECONDS for timeout in timeouts)


def test_an_mcp_read_waits_for_a_commit_instead_of_failing(tmp_path, capsys):
    import threading
    import time
    database, _ = _audited_store(tmp_path, capsys)
    _configure(database)
    expected = mcp_server.list_findings(DEVICE)
    holder = sqlite3.connect(str(database), isolation_level=None, check_same_thread=False)
    holder.execute("BEGIN EXCLUSIVE")

    def release():
        time.sleep(1.0)
        holder.execute("COMMIT")

    thread = threading.Thread(target=release)
    thread.start()
    try:
        assert mcp_server.list_findings(DEVICE) == expected
    finally:
        thread.join(30)
        holder.close()


def test_one_mcp_call_returns_the_previous_or_the_new_run_never_a_mix(tmp_path, capsys, monkeypatch):
    import threading
    from netops_auditor import cli
    from test_cli import clean_text, run_args, write_config
    database, _ = _audited_store(tmp_path, capsys)
    _configure(database)
    previous = mcp_server.list_findings(DEVICE)
    clean = write_config(tmp_path, clean_text(), name="clean.conf")
    real_connect = sqlite3.connect
    reading, released, committing = threading.Event(), threading.Event(), threading.Event()

    def reader_trace(statement):
        # Pause the reader inside its tool call, inside its read transaction, before it reads the runs.
        if reading.is_set() or "from runs" not in statement.lower():
            return
        reading.set()
        released.wait(30)

    def writer_trace(statement):
        if statement == "COMMIT":
            committing.set()

    def connect(*args, **keywords):
        connection = real_connect(*args, **keywords)
        name = threading.current_thread().name
        if name == "mcp-reader" and keywords.get("uri"):
            connection.set_trace_callback(reader_trace)
        elif name == "auditor-writer":
            connection.set_trace_callback(writer_trace)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    outcome = {}

    def read():
        try:
            outcome["read"] = mcp_server.list_findings(DEVICE)
        except Exception as error:
            outcome["read"] = repr(error)

    def write():
        outcome["write"] = cli.main(run_args(clean, store=database))

    reader = threading.Thread(target=read, name="mcp-reader")
    writer = threading.Thread(target=write, name="auditor-writer")
    reader.start()
    assert reading.wait(30)
    writer.start()
    try:
        assert committing.wait(30)
        writer.join(60)
        # The commit does not wait for the paused MCP call: in WAL its read transaction blocks no COMMIT.
        assert not writer.is_alive()
        assert reader.is_alive()
    finally:
        released.set()
        reader.join(30)
        writer.join(60)
    capsys.readouterr()
    assert outcome["write"] in (cli.EXIT_OK, cli.EXIT_STALE)
    assert outcome["read"] == previous
    current = mcp_server.list_findings(DEVICE)
    assert current["run_id"] != previous["run_id"]
    assert current["findings"] != previous["findings"]
