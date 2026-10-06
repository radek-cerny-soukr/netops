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
        keywords.setdefault("timeout", LOCK_WAIT_SECONDS)
        return real_connect(*args, **keywords)

    monkeypatch.setattr(sqlite3, "connect", connect)
    holder = real_connect(str(database), isolation_level=None)
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
