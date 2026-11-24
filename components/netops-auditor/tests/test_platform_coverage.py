import asyncio
import hashlib
import json

import pytest

from netops_auditor import engine, query
from netops_auditor.state import coverage
from netops_auditor.store import Store

pytest.importorskip("fastmcp")
from fastmcp import Client
from fastmcp.exceptions import ToolError
from netops_auditor import mcp_server


def version(key):
    return f"{key}:1:{hashlib.sha256(key.encode()).hexdigest()}"


def test_mixed_tenant_mcp_serializer_reads_only_committed_run_coverage(tmp_path, monkeypatch):
    store = tmp_path / "audit.sqlite"
    tenant = "example"
    statuses = {"exos.mgmt.telnet-enabled": {"status": "evaluated", "reason": "", "required": True}}
    with Store(store) as db:
        db.record_run(tenant, "switch", "a" * 64, "test", version("exos"), (), rule_status=statuses)
        db.record_run(tenant, "firewall", "b" * 64, "test", version("fortios"), ())
        db.record_run(tenant, "legacy", "c" * 64, "test", "fortios:4:old", ())
        db.record_run("other", "unrelated", "d" * 64, "test", version("exos"), ())
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", None)
    mcp_server.configure({mcp_server.STORE_VARIABLE: str(store), mcp_server.TENANT_VARIABLE: tenant,
                          mcp_server.CATALOG_VARIABLE: "fortios"})

    async def request():
        async with Client(mcp_server.mcp) as client:
            tools = await client.list_tools()
            listed = {tool.name: tool.inputSchema for tool in tools}
            assert set(listed) == set(mcp_server.TOOL_NAMES)
            for name in ("audit_status", "list_rules", "rule_detail", "findings_summary"):
                assert "platform" in listed[name]["properties"]
            result = await client.call_tool("audit_status", {"platform": "exos"})
            return json.loads(result.content[0].text)
    result = asyncio.run(request())
    assert [item["device"] for item in result["devices"]] == ["switch"]
    assert result["devices"][0]["coverage"]["counts"] == {"evaluated": 1, "not_evaluated": 0, "unsupported": 0}
    unfiltered = mcp_server.audit_status()
    assert next(item for item in unfiltered["devices"] if item["device"] == "legacy")["coverage"]["counts"] is None
    with pytest.raises(ToolError, match="catalog holds no rule"):
        mcp_server.findings_summary(device="switch", rule_id="exos.mgmt.telnet-enabled")
    assert mcp_server.findings_summary(platform="exos", rule_id="exos.mgmt.telnet-enabled")["returned"] == 0
    with pytest.raises(ToolError) as error:
        mcp_server.list_rules(platform="AuditU0CanaryValue")
    assert "AuditU0CanaryValue" not in str(error.value)


def test_marker_and_verified_prefix_for_new_platforms():
    assert not coverage([{"rule_id": "cisco-ios.snapshot.incomplete"}])["complete"]
    assert coverage([{"rule_id": "unspecified.snapshot.incomplete"}])["complete"]
    assert engine.run_platform(version("arista-eos") + ":" + "c" * 64) == "arista-eos"
    assert engine.run_platform("fortios:1:not-a-digest") is None
