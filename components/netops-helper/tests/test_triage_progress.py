"""Separate triage budget and progress reports of the triage tools (U4)."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from fastmcp import Client

from netops_core.audit import Recorder
import netops_helper.audit as audit
import netops_helper.engine as engine
import netops_helper.server as helper_server
from netops_helper import progress, proxy as proxy_module
from conftest import _target

import test_triage_health as health
import test_triage_routing as routing
import test_triage_slb as slb
import test_triage_vpn as vpn


@pytest.fixture()
def audit_log(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    return path


def collect():
    reports = []
    token = progress.bind(lambda done, total, message: reports.append((done, total, message)))
    return reports, token


# ---- the reporter -------------------------------------------------------------------------------

def test_every_triage_has_a_plan_and_the_proxy_charges_exactly_that_plan():
    assert set(progress.TRIAGE_READS) == {"triage_health", "triage_routing", "triage_vpn", "triage_slb"}
    assert proxy_module.TRIAGE_READS == {**progress.TRIAGE_READS, "triage_flow": 5, "wifi_triage": 7}
    assert proxy_module.TRIAGE_SLB_RATE_COST == 21 and proxy_module.TRIAGE_HEALTH_READS == 10


def test_steps_report_start_and_each_read_never_beyond_the_plan_and_survive_a_broken_channel():
    reports, token = collect()
    try:
        steps = progress.Steps("triage_vpn")
        for query in ("a", "b", "c", "d", "e", "f"):
            steps.read(query)
    finally:
        progress.unbind(token)
    assert [item[0] for item in reports] == [0, 1, 2, 3, 4, 4, 4]
    assert {item[1] for item in reports} == {4}
    assert reports[0][2].startswith("triage_vpn: 0 of at most 4 reads")

    def broken(*_):
        raise RuntimeError("channel gone")

    token = progress.bind(broken)
    try:
        progress.Steps("triage_vpn").read("a")  # must not raise
    finally:
        progress.unbind(token)
    progress.Steps("triage_vpn").read("a")      # unbound: silent


# ---- the engine reports once per device read --------------------------------------------------------

def test_triage_health_reports_each_read(audit_log, monkeypatch):
    values = health.outputs()
    monkeypatch.setattr(engine, "read_from_device", lambda auth, platform, command, **_: (0, values[health.COMMANDS[command]]))
    reports, token = collect()
    try:
        result = engine.triage_health(health._enrolled(*health.COMMANDS.values()))
    finally:
        progress.unbind(token)
    assert result["ok"] is True
    done = [item[0] for item in reports]
    assert done == sorted(done) and done[0] == 0 and done[-1] == 9 and len(done) == 10
    assert all(item[1] == 10 for item in reports) and "system_status" in reports[1][2]


def test_triage_routing_reports_each_read(audit_log, monkeypatch):
    values = routing.outputs()
    monkeypatch.setattr(engine, "read_from_device", lambda auth, platform, command, **_: (0, values[routing.COMMANDS[command]]))
    reports, token = collect()
    try:
        result = engine.triage_routing(routing._enrolled(*routing.COMMANDS.values()), routing.ADDRESS)
    finally:
        progress.unbind(token)
    assert result["ok"] is True
    assert [item[0] for item in reports] == [0, 1, 2, 3, 4, 5] and {item[1] for item in reports} == {5}


def test_triage_vpn_reports_each_read(audit_log, monkeypatch):
    values = vpn.outputs()
    monkeypatch.setattr(engine, "read_from_device", lambda auth, platform, command, **_: (0, values[vpn.COMMANDS[command]]))
    reports, token = collect()
    try:
        result = engine.triage_vpn(vpn._enrolled(*vpn.COMMANDS.values()), "T1")
    finally:
        progress.unbind(token)
    assert result["ok"] is True
    done = [item[0] for item in reports]
    assert done == sorted(done) and done[0] == 0 and done[-1] == 4 and {item[1] for item in reports} == {4}


def test_triage_slb_reports_each_read_within_the_charged_plan():
    reports, token = collect()
    try:
        result = slb.run(slb.Device())
    finally:
        progress.unbind(token)
    assert result["ok"] is True
    done = [item[0] for item in reports]
    assert done[0] == 0 and done == sorted(done) and len(done) >= 8
    assert done[-1] <= proxy_module.TRIAGE_SLB_RATE_COST and {item[1] for item in reports} == {21}
    assert reports[1][2] == "triage_slb: 1 of at most 21 reads (system_status)"
    assert all("\n" not in item[2] and len(item[2]) < 120 for item in reports)
    from netops.ipc import progress_report     # the gateway accepts every message the engine can produce
    assert all(progress_report({"progress": a, "total": b, "message": c}) is not None for a, b, c in reports)


def test_a_triage_refused_before_any_read_reports_nothing(audit_log, monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    reports, token = collect()
    try:
        with pytest.raises(ValueError):
            engine.triage_vpn(vpn._enrolled(*vpn.COMMANDS.values()), "T1;x")
    finally:
        progress.unbind(token)
    assert reports == []


# ---- the real MCP server --------------------------------------------------------------------------------

def fake_triage(auth, *arguments):
    steps = progress.Steps("triage_vpn")
    for query in ("system_status", "ike_gateway", "tunnel_list"):
        steps.read(query)
    return {"ok": True, "target": "wire-test"}


@pytest.fixture()
def real_server(monkeypatch):
    monkeypatch.setattr(helper_server, "_auth", lambda target, auth_context: SimpleNamespace(alias=target))
    monkeypatch.setattr(helper_server, "engine_triage_vpn", fake_triage)
    return helper_server.mcp


def test_the_real_server_sends_progress_notifications_when_the_client_asks(real_server):
    seen = []

    async def handler(done, total, message):
        seen.append((done, total, message))

    async def go():
        async with Client(real_server, progress_handler=handler) as client:
            return await client.call_tool("triage_vpn", {"target": "t", "tunnel": "T1"})

    result = asyncio.run(go())
    assert result.structured_content == {"ok": True, "target": "wire-test"}
    assert [item[0] for item in seen] == [0, 1, 2, 3]
    assert all(item[1] == 4 for item in seen) and seen[1][2].startswith("triage_vpn: 1 of at most 4 reads")


def test_the_real_server_sends_progress_only_to_a_request_with_a_progress_token(real_server):
    import httpx

    def call(token):
        params = {"name": "triage_vpn", "arguments": {"target": "t", "tunnel": "T1"}}
        if token is not None:
            params["_meta"] = {"progressToken": token}
        return {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params}

    async def post(message):
        app = real_server.http_app(path="/mcp", json_response=False, stateless_http=True)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/mcp", json=message, headers={
                    "Accept": "application/json, text/event-stream"})
        text = response.text.replace("\r\n", "\n")
        return [json.loads(line[6:]) for line in text.split("\n") if line.startswith("data: ")]

    silent = asyncio.run(post(call(None)))
    assert [m.get("method") for m in silent] == [None] and silent[0]["id"] == 5
    asked = asyncio.run(post(call("tok-9")))
    notifications = [m for m in asked if m.get("method") == "notifications/progress"]
    assert [m["params"]["progress"] for m in notifications] == [0, 1, 2, 3]
    assert all(m["params"]["progressToken"] == "tok-9" and m["params"]["total"] == 4 for m in notifications)
    assert asked[-1]["id"] == 5 and asked[-1]["result"]["structuredContent"] == {"ok": True, "target": "wire-test"}


def test_the_tool_schemas_do_not_show_the_context_parameter():
    async def go():
        async with Client(helper_server.mcp) as client:
            return {tool.name: tool.input_schema for tool in await client.list_tools()}

    schemas = asyncio.run(go())
    for name in ("triage_health", "triage_routing", "triage_vpn", "triage_slb"):
        assert "ctx" not in schemas[name]["properties"], name
        assert "ctx" not in schemas[name].get("required", [])
    assert set(schemas["triage_slb"]["properties"]) == {"target", "virtual_server", "vdom", "auth_context"}


def test_a_worker_transport_receives_ordered_reports_and_is_unbound_afterwards(real_server):
    got = []

    async def sink(done, total, message):
        got.append((done, total))

    async def go():
        token = progress.bind_transport(sink)
        try:
            return await real_server.call_tool("triage_vpn", {"target": "t", "tunnel": "T1"})
        finally:
            progress.unbind_transport(token)

    result = asyncio.run(go())
    assert result.structured_content["ok"] is True
    assert got == [(0, 4), (1, 4), (2, 4), (3, 4)]
    assert progress.transport() is None


def test_a_failing_sink_never_fails_the_triage(real_server):
    async def sink(done, total, message):
        raise RuntimeError("client went away")

    async def go():
        token = progress.bind_transport(sink)
        try:
            return await real_server.call_tool("triage_vpn", {"target": "t", "tunnel": "T1"})
        finally:
            progress.unbind_transport(token)

    assert asyncio.run(go()).structured_content["ok"] is True


def test_a_refusal_in_the_engine_still_reaches_the_client_as_a_tool_error(monkeypatch):
    monkeypatch.setattr(helper_server, "_auth", lambda target, auth_context: SimpleNamespace(alias=target))

    def refuse(auth, *arguments):
        raise ValueError("unsupported_platform: triage_vpn supports FortiOS targets only")

    monkeypatch.setattr(helper_server, "engine_triage_vpn", refuse)

    async def go():
        async with Client(helper_server.mcp) as client:
            return await client.call_tool("triage_vpn", {"target": "t", "tunnel": "T1"}, raise_on_error=False)

    result = asyncio.run(go())
    assert result.is_error and "unsupported_platform" in result.content[0].text


# ---- the separate budget ------------------------------------------------------------------------------------

LIMIT = {"requests": 30, "window_seconds": 60}
MANUAL = {"target": "device-a", "platform": "fortinet", "query": "system_status"}


@pytest.fixture()
def clock(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(proxy_module.time, "monotonic", lambda: now[0])
    return now


@pytest.mark.parametrize("triage_first", [True, False])
def test_mixed_traffic_obeys_the_original_total_cap_atomically(clock, triage_first):
    gateway = proxy_module.Proxy()
    if triage_first:
        gateway._consume_rate_limit("fg", LIMIT, 21, triage=True)
        for _ in range(9):
            gateway._consume_rate_limit("fg", LIMIT)
    else:
        for _ in range(9):
            gateway._consume_rate_limit("fg", LIMIT)
        gateway._consume_rate_limit("fg", LIMIT, 21, triage=True)
    assert gateway._rate_status("fg", LIMIT)["used"] == 30
    assert gateway._rate_status("fg", LIMIT, triage=True)["used"] == 21
    before = (list(gateway.rate_history["fg"]), list(gateway.triage_history["fg"]))
    for triage in (True, False):
        with pytest.raises(proxy_module.RateLimitError):
            gateway._consume_rate_limit("fg", LIMIT, triage=triage)
        assert (list(gateway.rate_history["fg"]), list(gateway.triage_history["fg"])) == before
    clock[0] = 160.0
    gateway._consume_rate_limit("fg", LIMIT, 21, triage=True)
    assert gateway._rate_status("fg", LIMIT)["used"] == 21
    assert gateway._rate_status("fg", LIMIT, triage=True)["used"] == 21


def test_a_manual_burst_refuses_triage_without_partial_accounting(clock):
    gateway = proxy_module.Proxy()
    gateway._consume_rate_limit("fg", LIMIT, 20)
    with pytest.raises(proxy_module.RateLimitError):
        gateway._consume_rate_limit("fg", LIMIT, 21, triage=True)
    assert gateway._rate_status("fg", LIMIT)["used"] == 20
    assert gateway._rate_status("fg", LIMIT, triage=True)["used"] == 0
    gateway._consume_rate_limit("fg", LIMIT, 10, triage=True)
    assert gateway._rate_status("fg", LIMIT)["remaining"] == 0


def test_the_triage_budget_is_still_a_budget_per_target_and_window(clock):
    gateway = proxy_module.Proxy()
    gateway._consume_rate_limit("fg", LIMIT, 21, triage=True)
    with pytest.raises(proxy_module.RateLimitError) as refused:
        gateway._consume_rate_limit("fg", LIMIT, 21, triage=True)     # a second slb triage does not fit
    assert refused.value.data["retry_after_seconds"] == 60
    with pytest.raises(proxy_module.RateLimitError):
        gateway._consume_rate_limit("fg", LIMIT, 10, triage=True)     # health no longer fits
    gateway._consume_rate_limit("fg", LIMIT, 5, triage=True)         # routing and VPN fit
    gateway._consume_rate_limit("fg", LIMIT, 4, triage=True)
    gateway._consume_rate_limit("other", LIMIT, 21, triage=True)      # another target has its own
    clock[0] = 161.0
    gateway._consume_rate_limit("fg", LIMIT, 21, triage=True)


def request_for(monkeypatch, tmp_path, tool, arguments, enabled):
    import test_proxy_contracts as contracts
    section = contracts._section()
    section["enabled_queries"] = enabled
    for name, path in (
        ("INVENTORY", contracts._write(tmp_path / "inventory.json", contracts._inventory(contracts._device(section)))),
        ("VAULT", contracts._write(tmp_path / "vault.json", contracts._vault_document(), 0o600)),
        ("EGRESS_POLICY", contracts._write(tmp_path / "egress-policy.json", contracts._egress_policy())),
        ("RUNNER", contracts._write(tmp_path / "runner.json", contracts._runner())),
    ):
        monkeypatch.setattr(proxy_module, name, path)
    return contracts


def test_proxy_requests_charge_triage_to_both_budgets(monkeypatch, tmp_path):
    contracts = request_for(monkeypatch, tmp_path, None, None, ["system_status", "route_lookup"])
    proxy = proxy_module.Proxy()
    assert proxy.request(contracts._request(1, "triage_health", {"target": "device-a"})) is not None
    assert len(proxy.triage_history["device-a"]) == 10 and len(proxy.rate_history["device-a"]) == 10
    assert proxy.request(contracts._request(2, "triage_vpn", {"target": "device-a", "tunnel": "T1"})) is not None
    assert len(proxy.triage_history["device-a"]) == 14
    assert proxy.request(contracts._request(3, "ssh_read", MANUAL)) is not None
    assert len(proxy.rate_history["device-a"]) == 15 and len(proxy.triage_history["device-a"]) == 14


def test_a_refused_triage_names_the_rate_limit_and_leaves_manual_work_possible(monkeypatch, tmp_path):
    contracts = request_for(monkeypatch, tmp_path, None, None, ["system_status", "route_lookup"])
    proxy = proxy_module.Proxy()
    emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    now = 500.0
    monkeypatch.setattr(proxy_module.time, "monotonic", lambda: now)
    proxy.triage_history["device-a"] = deque([now - 5.0] * 25)
    proxy.rate_history["device-a"] = deque([now - 5.0] * 25)
    assert proxy.request(contracts._request(4, "triage_health", {"target": "device-a"})) is None
    assert emitted[0]["error"]["data"]["category"] == "rate_limit"
    assert emitted[0]["error"]["data"]["retry_after_seconds"] == 55
    assert len(proxy.triage_history["device-a"]) == 25          # nothing was charged
    assert proxy.request(contracts._request(5, "ssh_read", MANUAL)) is not None


def test_target_scope_and_helper_status_show_both_budgets(monkeypatch, tmp_path):
    contracts = request_for(monkeypatch, tmp_path, None, None, ["system_status", "route_lookup"])
    proxy = proxy_module.Proxy()
    assert proxy.request(contracts._request(1, "triage_vpn", {"target": "device-a", "tunnel": "T1"})) is not None
    scope = proxy._target_scope_payload("device-a")
    assert scope["triage_rate_limit"]["used"] == 4 and scope["rate_limit"]["used"] == 4
    assert scope["triage_rate_limit"]["requests"] == scope["rate_limit"]["requests"] == 30
    status = proxy._helper_status_payload()["target_rate_limits"][0]
    assert status["triage_rate_limit"]["used"] == 4 and status["rate_limit"]["used"] == 4


@pytest.mark.parametrize("tool,arguments,expected", [
    ("triage_flow", {"src": "203.0.113.193", "dst": "203.0.113.194", "port": 443, "proto": "tcp"}, 5),
    ("wifi_triage", {"mac": "00:00:5e:00:53:01"}, 7),
])
def test_merged_triages_charge_both_budgets(monkeypatch, tmp_path, tool, arguments, expected):
    contracts = request_for(monkeypatch, tmp_path, tool, arguments,
                            ["system_status", "route_lookup", "policy_lookup_ipv4", "wifi_events"])
    proxy = proxy_module.Proxy()
    assert proxy.request(contracts._request(1, tool, {"target": "device-a", **arguments})) is not None
    assert len(proxy.rate_history["device-a"]) == expected
    assert len(proxy.triage_history["device-a"]) == expected
