from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

from netops_core.audit import Recorder
import pytest

from conftest import _target
import netops_helper.audit as audit
import netops_helper.engine as engine
from netops_helper import proxy as proxy_module
from netops_helper import triage_vpn as t

STATUS = "Version: FortiGate-60F v7.6.8,build3744,260115 (GA.M)\nVirtual domain configuration: disable\n"
SUMMARY = """'T1' 203.0.113.2:0  selectors(total,up): 1/1  rx(pkt,err): 1200/0  tx(pkt,err): 1180/0
'T10' 203.0.113.4:0  selectors(total,up): 1/0  rx(pkt,err): 0/0  tx(pkt,err): 0/4
"""
ROUTES = """Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
       O - OSPF, IA - OSPF inter area

Routing table for VRF=0
S*      0.0.0.0/0 [10/0] via 192.0.2.1, wan1, [1/0]
S       198.51.100.0/25 [10/0] via T1 tunnel 203.0.113.2, [1/0]
                     [10/0] via 192.0.2.9, wan2, [1/0]
B       198.51.100.128/25 [200/0] via 203.0.113.66 (recursive via T1 tunnel 203.0.113.2), 00:03:06
C       192.0.2.0/24 is directly connected, wan1
"""
IKE = """ike.decrypt: 0
ike.parse: 0
ike.neg.fail: 0 0
mem.fail: 0 0 0

"""
NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def outputs(**changes):
    values = {"system_status": STATUS, "ipsec_summary": SUMMARY, "routing_table": ROUTES, "ike_errors": IKE}
    values.update(changes)
    return values


def run(values, tunnel="T1", refused=()):
    calls = []

    def read(query):
        calls.append(query)
        if query in refused:
            return {"ok": False, "reason": refused[query] if isinstance(refused, dict) else "device_cli_error"}
        text = values[query]
        return {"ok": True, "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest()}

    ticks = iter(NOW + timedelta(seconds=n) for n in range(100))
    return t.run(read, lambda: next(ticks), tunnel), calls


def ids(result):
    return [item["id"] for item in result["findings"]]


def test_docs_sample_parses_into_the_contract_fields():
    result, calls = run(outputs())
    assert calls == ["system_status", "ipsec_summary", "routing_table", "ike_errors"]
    assert result["chain"]["tunnel"] == {"name": "T1", "instances": [
        {"name": "T1", "peer": "203.0.113.2:0", "selectors_total": 1, "selectors_up": 1,
         "rx_packets": 1200, "rx_errors": 0, "tx_packets": 1180, "tx_errors": 0}]}
    assert result["chain"]["routes"] == [{"prefix": "198.51.100.0/25", "code": "S", "interface": "T1"},
                                         {"prefix": "198.51.100.128/25", "code": "B", "interface": "T1"}]
    assert result["chain"]["ike_errors"] == {"counters": 4, "nonzero": {}}
    assert result["verdict"] == "no_fault_in_checked_data" and result["findings"] == []
    assert result["checked"] == ["system_status", "ipsec_summary", "routing_table", "ike_errors"]
    assert result["missing"] == [] and result["hypotheses"] == [] and result["next_steps"] == []
    assert result["identity"] == {"product": "FortiGate-60F", "version": "7.6.8", "build": "3744"}
    assert "healthy" not in json.dumps(result)


def test_down_tunnel_reports_down_and_its_errors_with_sources():
    result, _ = run(outputs(), tunnel="T10")
    assert ids(result) == ["F-VPN-DOWN", "F-VPN-ERRORS", "F-VPN-NO-ROUTE"]
    assert result["verdict"] == "fault_found"
    down = result["findings"][0]
    assert down["object"] == "vpn:T10" and down["layer"] == "runtime"
    assert down["fact"] == "selectors(total,up): 1/0"
    assert down["sources"] == [{"call": "triage_vpn", "query": "ipsec_summary",
                                "content_sha256": hashlib.sha256(SUMMARY.encode()).hexdigest(),
                                "captured_at": "2026-10-31T12:00:01Z"}]
    assert result["findings"][2]["sources"][0]["query"] == "routing_table"


@pytest.mark.parametrize("line,expected", [
    ("'T1' 198.51.100.1:0 selectors(total,up): 2/1 rx(pkt,err): 5/0 tx(pkt,err): 5/0", ["F-VPN-PARTIAL"]),
    ("'T1' 198.51.100.1:0 selectors(total,up): 2/2 rx(pkt,err): 5/0 tx(pkt,err): 5/0", []),
    ("'T1' 198.51.100.1:0 selectors(total,up): 1/1 rx(pkt,err): 0/0 tx(pkt,err): 9/0", ["F-VPN-NO-RX"]),
    ("'T1' 198.51.100.1:0 selectors(total,up): 1/1 rx(pkt,err): 1/0 tx(pkt,err): 9/0", []),
    ("'T1' 198.51.100.1:0 selectors(total,up): 1/1 rx(pkt,err): 1/1 tx(pkt,err): 9/0", ["F-VPN-ERRORS"]),
    ("'T1' 198.51.100.1:0 selectors(total,up): 1/1 rx(pkt,err): 1/0 tx(pkt,err): 9/1", ["F-VPN-ERRORS"]),
    ("'T1' 198.51.100.1:0 selectors(total,up): 1/0 rx(pkt,err): 0/0 tx(pkt,err): 0/0", ["F-VPN-DOWN"]),
])
def test_each_rule_and_its_boundary(line, expected):
    result, _ = run(outputs(ipsec_summary=line + "\n"))
    assert ids(result) == expected
    assert result["verdict"] == ("fault_found" if expected else "no_fault_in_checked_data")


def test_sa_up_without_received_packets_is_not_data_flow():
    line = "'T1' 198.51.100.1:0 selectors(total,up): 1/1 rx(pkt,err): 0/0 tx(pkt,err): 0/0\n"
    result, _ = run(outputs(ipsec_summary=line))
    assert result["findings"][0]["fact"] == "selectors up 1 but rx(pkt) 0"


def test_missing_tunnel_and_empty_summary_are_not_found():
    for text in (SUMMARY, ""):
        result, _ = run(outputs(ipsec_summary=text), tunnel="T2")
        assert ids(result) == ["F-VPN-NOT-FOUND"] and result["verdict"] == "fault_found"
        assert result["findings"][0]["object"] == "vpn:T2"
        assert result["chain"]["tunnel"] == {"name": "T2", "instances": []}


def test_similar_names_are_not_the_selected_tunnel():
    result, _ = run(outputs(), tunnel="T")
    assert ids(result) == ["F-VPN-NOT-FOUND"]
    result, _ = run(outputs(ipsec_summary=SUMMARY.replace("'T1'", "'T1x'")), tunnel="T1")
    assert ids(result) == ["F-VPN-NOT-FOUND"]


def test_dialup_instances_are_evaluated_each():
    text = ("'hub_0' 198.51.100.1:0 selectors(total,up): 1/1 rx(pkt,err): 7/0 tx(pkt,err): 7/0\n"
            "'hub_1' 198.51.100.2:0 selectors(total,up): 1/0 rx(pkt,err): 0/0 tx(pkt,err): 0/0\n")
    routes = ROUTES.replace("via T1 tunnel", "via hub_0 tunnel")
    result, _ = run(outputs(ipsec_summary=text, routing_table=routes), tunnel="hub")
    assert [i["name"] for i in result["chain"]["tunnel"]["instances"]] == ["hub_0", "hub_1"]
    assert [(f["id"], f["object"]) for f in result["findings"]] == [("F-VPN-DOWN", "vpn:hub_1")]
    assert {r["interface"] for r in result["chain"]["routes"]} == {"hub_0"}


@pytest.mark.parametrize("routes,expected", [
    ("Routing table for VRF=0\nC       198.51.100.0/24 is directly connected, T1\n",
     [{"prefix": "198.51.100.0/24", "code": "C", "interface": "T1"}]),
    ("Routing table for VRF=0\nS*      0.0.0.0/0 [10/0] via 192.0.2.1, wan1, [1/0]\n"
     "                     [10/0] via 203.0.113.1, T1, [1/0]\n",
     [{"prefix": "0.0.0.0/0", "code": "S*", "interface": "T1"}]),
    ("Routing table for VRF=0\nS       198.51.100.0/24 [10/0] via 192.0.2.1, wan1, [1/0]\n"
     "                     [10/0] via T1 tunnel 203.0.113.2, [1/0]\n",
     [{"prefix": "198.51.100.0/24", "code": "S", "interface": "T1"}]),
])
def test_route_via_tunnel_counts_from_any_line_form(routes, expected):
    result, _ = run(outputs(routing_table=routes))
    assert result["chain"]["routes"] == expected and ids(result) == []


def test_no_route_through_the_tunnel_is_a_finding():
    result, _ = run(outputs(routing_table=ROUTES.replace("via T1 tunnel", "via T10 tunnel")))
    assert ids(result) == ["F-VPN-NO-ROUTE"] and result["chain"]["routes"] == []
    assert result["findings"][0]["fact"] == "no route in routing-table via T1"


def test_ike_error_counters_are_context_only():
    result, _ = run(outputs(ike_errors=IKE.replace("ike.parse: 0", "ike.parse: 3").replace("ike.neg.fail: 0 0", "ike.neg.fail: 0 2")))
    assert result["chain"]["ike_errors"] == {"counters": 4, "nonzero": {"ike.parse": 3, "ike.neg.fail": 2}}
    assert ids(result) == [] and result["verdict"] == "no_fault_in_checked_data"


@pytest.mark.parametrize("step", ["ipsec_summary", "routing_table", "ike_errors"])
def test_a_refused_step_is_incomplete_never_clean(step):
    result, calls = run(outputs(), refused=(step,))
    assert result["verdict"] == "incomplete"
    assert {"step": step, "reason": "device_cli_error"} in result["missing"]
    assert step not in result["checked"] and len(calls) == 4


def test_findings_survive_a_missing_step_and_route_rule_needs_routes():
    result, _ = run(outputs(), tunnel="T10", refused={"routing_table": "timeout"})
    assert ids(result) == ["F-VPN-DOWN", "F-VPN-ERRORS"]
    assert result["missing"] == [{"step": "routing_table", "reason": "timeout"}]
    assert result["verdict"] == "incomplete"
    result, _ = run(outputs(), refused={"ipsec_summary": "permission_denied"})
    assert ids(result) == [] and result["chain"]["tunnel"] == {"name": "T1", "instances": None}


@pytest.mark.parametrize("query,text", [
    ("ipsec_summary", "'T1' 198.51.100.1:0 selectors(total,up): 1/1 rx(pkt,err): 1/0\n"),
    ("ipsec_summary", SUMMARY + "unexpected line\n"),
    ("routing_table", "Routing table for VRF=0\n"),
    ("routing_table", "garbage only\n"),
    ("ike_errors", "ike.parse: x\n"),
    ("ike_errors", IKE + "free text\n"),
])
def test_unknown_shape_is_unparsed_and_incomplete(query, text):
    result, _ = run(outputs(**{query: text}))
    assert {"step": query, "reason": "unparsed"} in result["missing"]
    assert result["verdict"] == "incomplete"


def test_empty_routing_or_ike_output_is_empty_not_clean():
    result, _ = run(outputs(ike_errors=""))
    assert {"step": "ike_errors", "reason": "empty"} in result["missing"] and result["verdict"] == "incomplete"


@pytest.mark.parametrize("status", [
    "Version: FortiGate-80F v8.0.1,build0251,260928 (GA.F)\n",
    "Version: FortiGate-VM64 v7.6.8,build3744,260115 (GA.M)\n",
])
def test_unqualified_identity_stops_before_any_other_read(status):
    calls = []

    def read(query):
        calls.append(query)
        return {"ok": True, "text": status, "content_sha256": "0" * 64}

    with pytest.raises(t.UnsupportedPlatform, match="config_platform_not_supported"):
        t.run(read, lambda: NOW, "T1")
    assert calls == ["system_status"]


def test_measured_fortigate_80f_802_identity_proceeds():
    result, _ = run(outputs(system_status="Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)\n"))
    assert result["identity"]["product"] == "FortiGate-80F"


@pytest.mark.parametrize("name", ["", "T 1", "T1;show", "-T1", "a" * 36, "T'1", 7, None])
def test_invalid_tunnel_name_is_refused_before_any_read(name):
    calls = []
    with pytest.raises(ValueError, match="invalid_argument"):
        t.run(lambda query: calls.append(query), lambda: NOW, name)
    assert calls == []


COMMANDS = {
    "get system status": "system_status", "get vpn ipsec tunnel summary": "ipsec_summary",
    "get router info routing-table all": "routing_table", "diagnose vpn ike errors": "ike_errors",
}


@pytest.fixture()
def audit_log(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    return path


def _enrolled(*queries):
    from dataclasses import replace
    return replace(_target("fortinet", "system_status"), enabled_queries=tuple(queries))


def test_engine_reads_each_query_once_never_with_the_tunnel_name_and_audits(audit_log, monkeypatch):
    sent = []
    values = outputs()

    def device(auth, platform, command, **_):
        sent.append(command)
        return 0, values[COMMANDS[command]]

    monkeypatch.setattr(engine, "read_from_device", device)
    result = engine.triage_vpn(_enrolled(*COMMANDS.values()), "T1")
    assert result["ok"] is True and result["target"] == "wire-test" and result["tunnel"] == "T1"
    assert result["verdict"] == "no_fault_in_checked_data"
    assert sent == list(COMMANDS)
    records = [json.loads(line) for line in audit_log.read_text().splitlines()]
    assert [r["event"] for r in records].count("triage_vpn_read") == 8
    assert records[0]["event"] == "triage_vpn" and records[-1]["event"] == "triage_vpn"
    assert {r.get("query") for r in records if r["event"] == "triage_vpn_read"} == set(COMMANDS.values())


def test_engine_maps_policy_and_device_refusal_to_missing(audit_log, monkeypatch):
    values = outputs()

    def device(auth, platform, command, **_):
        if command == "diagnose vpn ike errors":
            return 0, "Command fail. Return code -37"
        return 0, values[COMMANDS[command]]

    monkeypatch.setattr(engine, "read_from_device", device)
    enabled = [q for q in COMMANDS.values() if q != "routing_table"]
    result = engine.triage_vpn(_enrolled(*enabled), "T1")
    assert {"step": "routing_table", "reason": "permission_denied"} in result["missing"]
    assert {"step": "ike_errors", "reason": "device_cli_error"} in result["missing"]
    assert result["verdict"] == "incomplete"


def test_engine_refuses_other_platforms_and_bad_names_before_device_contact(audit_log, monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    with pytest.raises(ValueError, match="unsupported_platform"):
        engine.triage_vpn(_target("fortiadc", "system_status"), "T1")
    with pytest.raises(ValueError, match="invalid_argument"):
        engine.triage_vpn(_enrolled(*COMMANDS.values()), "T1;x")


def test_engine_redacts_secrets_before_parsing(audit_log, monkeypatch):
    values = outputs()
    seen = {}

    def device(auth, platform, command, **_):
        text = values[COMMANDS[command]]
        if command == "get vpn ipsec tunnel summary":
            text = text.replace("'T10'", "'" + auth.secret + "'")
        return 0, text

    monkeypatch.setattr(engine, "read_from_device", device)
    original = t.ipsec_summary
    monkeypatch.setattr(t, "PARSERS", {**t.PARSERS, "ipsec_summary": lambda text: seen.setdefault("text", text) and original(text)})
    target = _enrolled(*COMMANDS.values())
    engine.triage_vpn(target, "T1")
    assert target.secret not in seen["text"]


def test_proxy_accepts_target_and_tunnel_only_and_charges_the_whole_plan(monkeypatch):
    Proxy = proxy_module.Proxy
    assert Proxy._validate_tool_arguments("triage_vpn", {"target": "fg", "tunnel": "T1"}) == {"target": "fg", "tunnel": "T1"}
    for bad in ({"target": "fg"}, {"target": "fg", "tunnel": "T1", "query": "x"}, {"target": "fg", "tunnel": "T 1"},
                {"target": "fg", "tunnel": 5}, {"target": "fg", "tunnel": "a" * 36}):
        with pytest.raises(proxy_module.ToolArgumentsError):
            Proxy._validate_tool_arguments("triage_vpn", bad)
    from types import SimpleNamespace
    section = SimpleNamespace(egress={}, catalog_platform=lambda: "fortinet", enabled_queries=("system_status",),
                              read_inventory={})
    Proxy._authorize_tool("triage_vpn", {"target": "fg", "tunnel": "T1"}, None, section)
    for changed in (SimpleNamespace(egress={}, catalog_platform=lambda: "fortiadc", enabled_queries=("system_status",)),
                    SimpleNamespace(egress={}, catalog_platform=lambda: "fortinet", enabled_queries=("performance",))):
        with pytest.raises(proxy_module.PolicyScopeError):
            Proxy._authorize_tool("triage_vpn", {"target": "fg", "tunnel": "T1"}, None, changed)
    proxy = Proxy()
    monkeypatch.setattr(proxy_module.time, "monotonic", lambda: 100.0)
    limit = {"requests": 30, "window_seconds": 60}
    proxy.rate_history["fg"] = deque([90.0] * 27)
    with pytest.raises(proxy_module.RateLimitError):
        proxy._consume_rate_limit("fg", limit, proxy_module.TRIAGE_VPN_READS)
    proxy.rate_history["fg"] = deque([90.0] * 26)
    proxy._consume_rate_limit("fg", limit, proxy_module.TRIAGE_VPN_READS)
    assert len(proxy.rate_history["fg"]) == 30
    assert proxy_module.TRIAGE_VPN_READS == t.PLANNED_READS == 4
