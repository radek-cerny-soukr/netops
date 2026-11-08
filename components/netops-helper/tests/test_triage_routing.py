from __future__ import annotations

from collections import deque
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from netops_core.audit import Recorder
import pytest

from conftest import _target
import netops_helper.audit as audit
import netops_helper.engine as engine
from netops_helper import proxy as proxy_module
from netops_helper import triage_routing as t

ADDRESS = "198.51.100.20"
STATUS = "Version: FortiGate-60F v7.6.8,build3744,260115 (GA.M)\nVirtual domain configuration: disable\n"
ROUTE_STATIC = """Routing table for VRF=0
Routing entry for 0.0.0.0/0
  Known via "static", distance 1, metric 0, best
  * vrf 0 192.0.2.1, via wan1
  * vrf 0 203.0.113.1, via wan2
"""
ROUTE_CONNECTED = """Routing table for VRF=0
Routing entry for 198.51.100.0/24
  Known via "connected", distance 0, metric 0, best
  * is directly connected, internal
"""
ROUTE_BGP = """Routing table for VRF=0
Routing entry for 203.0.113.0/24
  Known via "bgp", distance 200, metric 0, best
  Last update 01:35:35 ago
  * vrf 0 192.0.2.65 priority 1 (recursive via EDGE_T3 tunnel 192.0.2.7 [1])
                                               (recursive via EDGE_T1 tunnel 192.0.2.65 [10])
"""
ROUTE_NONE = "Routing table for VRF=0\n% Network not in table\n"
PROUTE_EMPTY = "list route policy info(vf=root):\n\n"
PROUTE = """list route policy info(vf=root):

id=1(0x01) vwl_service=1(Critical-DIA) vwl_mbr_seq=1 2 dscp_tag=0xfc 0xfc flags=0x0 tos=0x00 tos_mask=0x00 protocol=0 sport=0-65535 iif=0(any) dport=1-65535 path(2) oif=3(wan1) oif=4(wan2)
source(1): 192.0.2.0-192.0.2.255
destination(1): 198.51.100.0-198.51.100.255
hit_count=0 last_used=2026-10-30 10:20:31

id=2 dscp_tag=0xff 0xff flags=0x0 tos=0x00 tos_mask=0x00 protocol=0 sport=0-65535 iif=5(internal) dport=0-65535 oif=4(wan2) gwy=203.0.113.1
source wildcard(1): 0.0.0.0/0.0.0.0
destination wildcard(1): 203.0.113.0/255.255.255.0
hit_count=3 last_used=2026-10-30 10:21:00
"""
SDWAN = """Health Check(ping_server):
Seq(1 wan1): state(alive), packet-loss(0.000%) latency(15.247), jitter(5.231) sla_map=0x0
Seq(2 wan2): state(alive), packet-loss(0.000%) latency(13.621), jitter(6.905) sla_map=0x0
"""
ARP = """Address           Age(min)   Hardware Addr      Interface
192.0.2.1         0          00:00:5e:00:53:01 wan1
203.0.113.1       1          00:00:5e:00:53:02 wan2
"""
NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def outputs(**changes):
    values = {"system_status": STATUS, "route_lookup": ROUTE_STATIC, "policy_routes_ipv4": PROUTE_EMPTY,
              "sdwan_health": SDWAN, "arp_table": ARP}
    values.update(changes)
    return values


def run(values, refused=()):
    calls = []

    def read(query, parameters):
        calls.append((query, parameters))
        if query in refused:
            return {"ok": False, "reason": refused[query] if isinstance(refused, dict) else "device_cli_error"}
        text = values[query]
        return {"ok": True, "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest()}

    ticks = iter(NOW + timedelta(seconds=n) for n in range(100))
    return t.run(read, lambda: next(ticks), ADDRESS), calls


def ids(items):
    return [item["id"] for item in items]


def test_clean_chain_is_never_called_healthy_and_says_what_is_not_simulated():
    result, calls = run(outputs())
    assert calls == [("system_status", None), ("route_lookup", {"address": ADDRESS}), ("policy_routes_ipv4", None),
                     ("sdwan_health", None), ("arp_table", None)]
    assert result["identity"] == {"product": "FortiGate-60F", "version": "7.6.8", "build": "3744"}
    assert result["verdict"] == "no_fault_in_checked_data" and result["findings"] == [] and result["hypotheses"] == []
    assert result["dataplane_simulated"] is False and len(result["not_simulated"]) == 4
    assert result["checked"] == list(t.STEPS) and result["missing"] == []
    route = result["chain"]["route"]
    assert route["prefix"] == "0.0.0.0/0" and route["protocol"] == "static" and route["best"] is True
    assert [(h["gateway"], h["interface"], h["fib"]) for h in route["next_hops"]] == [
        ("192.0.2.1", "wan1", True), ("203.0.113.1", "wan2", True)]
    assert result["chain"]["gateways"] == [{"gateway": "192.0.2.1", "arp": "complete"},
                                           {"gateway": "203.0.113.1", "arp": "complete"}]
    assert [m["seq"] for m in result["chain"]["sdwan"]["egress_members"]] == [1, 2]
    assert result["chain"]["policy_routes"] == {"entries": 0, "covering": [], "unevaluated": []}
    assert result["started_at"] == "2026-10-31T12:00:00Z" and "healthy" not in json.dumps(result)


def test_no_route_is_a_sourced_finding_with_a_catalog_next_step():
    result, _ = run(outputs(route_lookup=ROUTE_NONE))
    assert ids(result["findings"]) == ["F-ROUTE-NONE"] and result["verdict"] == "fault_found"
    finding = result["findings"][0]
    assert finding["fact"] == "% Network not in table" and finding["object"] == "route:" + ADDRESS
    assert finding["sources"] == [{"call": "triage_routing", "query": "route_lookup",
                                   "content_sha256": hashlib.sha256(ROUTE_NONE.encode()).hexdigest(),
                                   "captured_at": "2026-10-31T12:00:01Z"}]
    assert result["next_steps"] == [{"tool": "ssh_read", "arguments": {"platform": "fortinet", "query": "routing_table"},
                                     "why": "full IPv4 table: which covering or default route is absent"}]
    assert result["chain"]["route"] is None and result["chain"]["gateways"] is None


def test_dead_sdwan_member_on_the_egress_is_a_finding_citing_both_reads():
    result, _ = run(outputs(sdwan_health=SDWAN.replace("Seq(2 wan2): state(alive)", "Seq(2 wan2): state(dead)")))
    assert ids(result["findings"]) == ["F-EGRESS-SDWAN-DEAD"] and result["verdict"] == "fault_found"
    finding = result["findings"][0]
    assert finding["object"] == "sdwan:ping_server:2"
    assert [s["query"] for s in finding["sources"]] == ["route_lookup", "sdwan_health"]
    assert result["next_steps"][0]["arguments"] == {"platform": "fortinet", "query": "sdwan_member_detail",
                                                    "parameters": {"member": "2"}}


def test_next_hop_outside_the_fib_is_not_judged():
    route = ROUTE_STATIC.replace("  * vrf 0 203.0.113.1, via wan2", "    vrf 0 203.0.113.1, via wan2")
    sdwan = SDWAN.replace("Seq(2 wan2): state(alive)", "Seq(2 wan2): state(dead)")
    result, _ = run(outputs(route_lookup=route, sdwan_health=sdwan, arp_table=ARP.replace("00:00:5e:00:53:02", "00:00:00:00:00:00")))
    assert result["chain"]["route"]["next_hops"][1]["fib"] is False
    assert result["findings"] == [] and [m["seq"] for m in result["chain"]["sdwan"]["egress_members"]] == [1]


def test_dead_member_off_the_egress_path_is_no_finding():
    sdwan = SDWAN + "Seq(3 lte1): state(dead), packet-loss(100.000%), sla_map=0x0\n"
    result, _ = run(outputs(sdwan_health=sdwan))
    assert result["findings"] == [] and result["verdict"] == "no_fault_in_checked_data"


def test_incomplete_gateway_arp_is_a_finding_but_absence_is_only_a_hypothesis():
    result, _ = run(outputs(arp_table=ARP.replace("00:00:5e:00:53:01", "00:00:00:00:00:00")))
    assert ids(result["findings"]) == ["F-NEXTHOP-ARP-INCOMPLETE"]
    assert result["chain"]["gateways"][0] == {"gateway": "192.0.2.1", "arp": "incomplete"}
    result, _ = run(outputs(arp_table=ARP.replace("192.0.2.1 ", "192.0.2.9 ")))
    assert result["findings"] == [] and ids(result["hypotheses"]) == ["H-NEXTHOP-NO-ARP"]
    assert "gateway 192.0.2.1 is not in the ARP table" in result["hypotheses"][0]["text"]
    assert result["verdict"] == "no_fault_in_checked_data"
    assert result["chain"]["gateways"][0] == {"gateway": "192.0.2.1", "arp": "absent"}


def test_gateway_arp_is_correlated_by_egress_interface():
    incomplete = "192.0.2.1         0          00:00:00:00:00:00 wan1\n"
    header = "Address           Age(min)   Hardware Addr      Interface\n"
    other = "192.0.2.1         0          00:00:5e:00:53:01 wan2\n"
    route = ROUTE_STATIC.replace("  * vrf 0 203.0.113.1, via wan2\n", "")
    result, _ = run(outputs(route_lookup=route, arp_table=header + incomplete))
    assert ids(result["findings"]) == ["F-NEXTHOP-ARP-INCOMPLETE"] and result["verdict"] == "fault_found"
    assert result["chain"]["gateways"] == [{"gateway": "192.0.2.1", "arp": "incomplete"}]
    result, _ = run(outputs(route_lookup=route, arp_table=header + incomplete + other))
    assert ids(result["findings"]) == ["F-NEXTHOP-ARP-INCOMPLETE"] and result["verdict"] == "fault_found"
    assert result["chain"]["gateways"] == [{"gateway": "192.0.2.1", "arp": "incomplete"}]
    result, _ = run(outputs(route_lookup=route, arp_table=header + other))
    assert result["findings"] == [] and ids(result["hypotheses"]) == ["H-NEXTHOP-NO-ARP"]
    text = result["hypotheses"][0]["text"]
    assert "no ARP entry on egress interface wan1" in text and "only on another interface" in text
    assert "is not in the ARP table" not in text
    assert result["chain"]["gateways"] == [{"gateway": "192.0.2.1", "arp": "absent"}]


def test_gateway_arp_is_unknown_when_the_egress_interface_is_not_known():
    route = ROUTE_STATIC.replace("  * vrf 0 192.0.2.1, via wan1\n", "  * vrf 0 192.0.2.1\n").replace(
        "  * vrf 0 203.0.113.1, via wan2\n", "")
    arp = "Address           Age(min)   Hardware Addr      Interface\n192.0.2.1         0          00:00:00:00:00:00 wan1\n"
    result, _ = run(outputs(route_lookup=route, arp_table=arp))
    assert result["chain"]["route"]["next_hops"][0]["interface"] is None
    assert result["findings"] == [] and result["hypotheses"] == []
    assert result["chain"]["gateways"] == [{"gateway": "192.0.2.1", "arp": "unknown"}]


def test_connected_and_recursive_routes_are_not_checked_against_arp_or_sdwan():
    result, _ = run(outputs(route_lookup=ROUTE_CONNECTED, arp_table="Address  Age(min)  Hardware Addr  Interface\n"))
    assert result["chain"]["route"]["next_hops"] == [{"fib": True, "gateway": None, "interface": "internal",
                                                      "recursive": []}]
    assert result["findings"] == [] and result["hypotheses"] == [] and result["chain"]["gateways"] == []
    result, _ = run(outputs(route_lookup=ROUTE_BGP, arp_table="Address  Age(min)  Hardware Addr  Interface\n"))
    hop = result["chain"]["route"]["next_hops"][0]
    assert hop["gateway"] == "192.0.2.65" and hop["interface"] is None and hop["recursive"] == ["EDGE_T3", "EDGE_T1"]
    assert result["findings"] == [] and result["hypotheses"] == []


def test_covering_policy_route_is_a_hypothesis_not_a_finding():
    result, _ = run(outputs(policy_routes_ipv4=PROUTE))
    assert result["chain"]["policy_routes"] == {
        "entries": 2, "unevaluated": [],
        "covering": [{"id": 1, "service": "Critical-DIA", "oif": ["wan1", "wan2"], "gateway": None}]}
    assert ids(result["hypotheses"]) == ["H-POLICY-ROUTE"] and result["findings"] == []
    assert "SD-WAN rule Critical-DIA" in result["hypotheses"][0]["text"]
    assert result["verdict"] == "no_fault_in_checked_data"


@pytest.mark.parametrize("destination,covered", [
    ("destination wildcard(1): 198.51.100.0/255.255.255.0", True),
    ("destination wildcard(1): 0.0.0.0/0.0.0.0", True),
    ("destination wildcard(1): 203.0.113.0/255.255.255.0", False),
    ("destination(1): 198.51.100.20", True),
    ("destination(1): 198.51.100.21", False),
    ("destination(2): 192.0.2.0-192.0.2.255 198.51.100.20-198.51.100.30", True),
    ("destination(1): 198.51.100.21-198.51.100.30", False),
])
def test_policy_route_destination_forms(destination, covered):
    text = "list route policy info(vf=root):\nid=7 oif=3(wan1) gwy=192.0.2.1\n" + destination + "\n"
    result = t.policy_routes(text, ADDRESS)
    assert result["entries"] == 1 and bool(result["covering"]) is covered and result["unevaluated"] == []


@pytest.mark.parametrize("extra", [
    "internet service(1): Google-Gmail(65646,0,0,0)",
    "dst_negate=1",
])
def test_internet_service_and_negation_are_unevaluated(extra):
    text = ("list route policy info(vf=root):\nid=9 oif=3(wan1)\n" + extra +
            "\ndestination(1): 198.51.100.0-198.51.100.255\n")
    result, _ = run(outputs(policy_routes_ipv4=text))
    assert result["chain"]["policy_routes"]["covering"] == [] and result["chain"]["policy_routes"]["unevaluated"] == [9]
    assert ids(result["hypotheses"]) == ["H-POLICY-UNEVALUATED"]


PROUTE_PATH_LINE = """list route policy info(vf=root):

id=1(0x01) dscp_tag=0xfc 0xfc flags=0x0 tos=0x00 tos_mask=0x00 protocol=0 port=src(0->0):dst(0->0) iif=7(lan)
path(1): oif=5(wan1) gwy=192.0.2.1 path_last_used=2026-10-30 10:20:31
source wildcard(1): 0.0.0.0/0.0.0.0
destination wildcard(1): 198.51.100.0/255.255.255.0
hit_count=4 rule_last_used=2026-10-30 10:20:31

id=2(0x02) dscp_tag=0xfc 0xfc flags=0x2 dst-negate tos=0x00 tos_mask=0x00 protocol=0 port=src(0->0):dst(0->0) iif=7(lan)
path(1): oif=6(wan2) gwy=203.0.113.1 path_last_used=2026-10-30 10:20:31
source wildcard(1): 0.0.0.0/0.0.0.0
destination wildcard(2): 192.0.2.0/255.255.255.0 203.0.113.0/255.255.255.0
hit_count=9 rule_last_used=2026-10-30 10:20:31
"""


def test_path_line_carries_egress_and_dst_negate_flag_is_unevaluated():
    result = t.policy_routes(PROUTE_PATH_LINE, ADDRESS)
    assert result == {"entries": 2, "unevaluated": [2],
                      "covering": [{"id": 1, "service": None, "oif": ["wan1"], "gateway": "192.0.2.1"}]}


def test_negate_zero_is_still_evaluated():
    text = "list route policy info(vf=root):\nid=9 oif=3(wan1) dst_negate=0\ndestination(1): 198.51.100.20\n"
    assert t.policy_routes(text, ADDRESS)["covering"][0]["id"] == 9


@pytest.mark.parametrize("step", ["arp_table", "policy_routes_ipv4", "route_lookup"])
def test_a_refused_required_step_is_incomplete_never_clean(step):
    result, _ = run(outputs(), refused={step: "permission_denied"})
    assert {"step": step, "reason": "permission_denied"} in result["missing"]
    assert result["verdict"] == "incomplete" and step not in result["checked"]


def test_unknown_refusal_reason_becomes_device_cli_error_and_findings_survive():
    result, _ = run(outputs(route_lookup=ROUTE_NONE), refused={"arp_table": "weird"})
    assert {"step": "arp_table", "reason": "device_cli_error"} in result["missing"]
    assert ids(result["findings"]) == ["F-ROUTE-NONE"] and result["verdict"] == "incomplete"


@pytest.mark.parametrize("text", ["", "SD-WAN health monitor is not running.\n", "SD-WAN daemon is not running.\n"])
def test_sdwan_not_running_is_not_applicable_and_not_a_gap(text):
    result, _ = run(outputs(sdwan_health=text))
    assert result["missing"] == [{"step": "sdwan_health", "reason": "not_applicable"}]
    assert result["verdict"] == "no_fault_in_checked_data" and result["chain"]["sdwan"] is None


@pytest.mark.parametrize("step", ["route_lookup", "policy_routes_ipv4", "arp_table"])
def test_empty_required_output_is_empty_not_zero(step):
    result, _ = run(outputs(**{step: "  \n"}))
    assert {"step": step, "reason": "empty"} in result["missing"] and result["verdict"] == "incomplete"


@pytest.mark.parametrize("query,text", [
    ("route_lookup", ROUTE_STATIC + "  something new\n"),
    ("route_lookup", "Routing table for VRF=0\nRouting entry for 0.0.0.0/0\n"),
    ("route_lookup", ROUTE_STATIC.replace("Known via", "Learned via")),
    ("route_lookup", ROUTE_STATIC.replace("192.0.2.1,", "192.0.2.999,")),
    ("route_lookup", ROUTE_NONE + ROUTE_STATIC),
    ("policy_routes_ipv4", "id=1 oif=3(wan1)\ndestination(2): 198.51.100.20\n"),
    ("policy_routes_ipv4", "garbage\nid=1 oif=3(wan1)\n"),
    ("policy_routes_ipv4", "id=1 oif=3(wan1)\ndestination(1): 198.51.100.x\n"),
    ("policy_routes_ipv4", "id=1 oif=3(wan1)\ndestination list: 198.51.100.20\n"),
    ("arp_table", "192.0.2.1 0 00:00:5e:00:53:01 wan1\n"),
    ("arp_table", ARP + "192.0.2.7 incomplete\n"),
    ("sdwan_health", "Seq(1 wan1): state(alive)\n"),
])
def test_unknown_shape_is_unparsed_and_incomplete(query, text):
    result, _ = run(outputs(**{query: text}))
    assert {"step": query, "reason": "unparsed"} in result["missing"]
    assert result["verdict"] == "incomplete" and query not in result["checked"]


@pytest.mark.parametrize("status", [
    "Version: FortiGate-60F v7.6.7,build3700,250101 (GA.M)\n",
    "Version: FortiGate-80F v8.0.2,build0251,260101 (GA.F)\n",
    "no version here\n",
])
def test_unqualified_identity_stops_before_any_other_read(status):
    calls = []

    def read(query, parameters):
        calls.append(query)
        return {"ok": True, "text": status, "content_sha256": "0" * 64}

    with pytest.raises(t.UnsupportedPlatform, match="config_platform_not_supported"):
        t.run(read, lambda: NOW, ADDRESS)
    assert calls == ["system_status"]


def test_failed_identity_read_is_not_supported():
    with pytest.raises(t.UnsupportedPlatform):
        t.run(lambda q, p: {"ok": False, "reason": "timeout"}, lambda: NOW, ADDRESS)


COMMANDS = {
    "get system status": "system_status",
    "get router info routing-table details " + ADDRESS: "route_lookup",
    "diagnose firewall proute list": "policy_routes_ipv4",
    "diagnose sys sdwan health-check": "sdwan_health",
    "get system arp": "arp_table",
}


@pytest.fixture()
def audit_log(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    return path


def _enrolled(*queries, addresses=(ADDRESS,)):
    return replace(_target("fortinet", "system_status"), enabled_queries=tuple(queries),
                   read_inventory={"addresses": tuple(addresses)})


def test_engine_reads_the_fixed_chain_once_and_audits_every_read(audit_log, monkeypatch):
    sent = []
    values = outputs()

    def device(auth, platform, command, **_):
        sent.append(command)
        return 0, values[COMMANDS[command]]

    monkeypatch.setattr(engine, "read_from_device", device)
    result = engine.triage_routing(_enrolled(*COMMANDS.values()), ADDRESS)
    assert result["ok"] is True and result["target"] == "wire-test" and result["address"] == ADDRESS
    assert result["verdict"] == "no_fault_in_checked_data"
    assert sent == list(COMMANDS)
    records = [json.loads(line) for line in audit_log.read_text().splitlines()]
    events = [r["event"] for r in records]
    assert events.count("triage_health_read") == 10
    assert events[0] == "triage_routing" and events[-1] == "triage_routing"
    assert "untrusted_device_output" not in result


def test_engine_maps_disabled_query_to_permission_denied(audit_log, monkeypatch):
    values = outputs()
    monkeypatch.setattr(engine, "read_from_device", lambda auth, platform, command, **_: (0, values[COMMANDS[command]]))
    enabled = [q for q in COMMANDS.values() if q != "arp_table"]
    result = engine.triage_routing(_enrolled(*enabled), ADDRESS)
    assert {"step": "arp_table", "reason": "permission_denied"} in result["missing"]
    assert result["verdict"] == "incomplete"


@pytest.mark.parametrize("address", ["198.51.100.21", "198.51.100.020", "2001:db8::1", "", None])
def test_engine_refuses_unenrolled_or_malformed_address_before_device_contact(audit_log, monkeypatch, address):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    with pytest.raises(ValueError, match="enrolled IPv4"):
        engine.triage_routing(_enrolled(*COMMANDS.values()), address)


def test_engine_refuses_other_platforms_before_device_contact(audit_log, monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    with pytest.raises(ValueError, match="unsupported_platform"):
        engine.triage_routing(_target("fortiadc", "system_status"), ADDRESS)


@pytest.mark.parametrize("tool,arguments,cost", [
    ("triage_routing", {"target": "device-a", "address": "192.0.2.20"}, 5),
    ("triage_health", {"target": "device-a"}, 10),
])
def test_proxy_call_charges_the_planned_reads(monkeypatch, tmp_path, tool, arguments, cost):
    import test_proxy_contracts as contracts
    section = contracts._section()
    section["enabled_queries"] = ["system_status", "route_lookup"]
    for name, path in (
        ("INVENTORY", contracts._write(tmp_path / "inventory.json", contracts._inventory(contracts._device(section)))),
        ("VAULT", contracts._write(tmp_path / "vault.json", contracts._vault_document(), 0o600)),
        ("EGRESS_POLICY", contracts._write(tmp_path / "egress-policy.json", contracts._egress_policy())),
        ("RUNNER", contracts._write(tmp_path / "runner.json", contracts._runner())),
    ):
        monkeypatch.setattr(proxy_module, name, path)
    proxy = proxy_module.Proxy()
    assert proxy.request(contracts._request(1, tool, arguments)) is not None
    assert len(proxy.rate_history["device-a"]) == cost


def test_proxy_requires_an_enrolled_address_and_charges_the_whole_plan(monkeypatch):
    Proxy = proxy_module.Proxy
    args = {"target": "fg", "address": ADDRESS}
    assert Proxy._validate_tool_arguments("triage_routing", dict(args)) == args
    for bad in ({"target": "fg"}, {**args, "query": "x"}, {"target": "fg", "address": "198.51.100.300"},
                {"target": "fg", "address": 5}):
        with pytest.raises(proxy_module.ToolArgumentsError):
            Proxy._validate_tool_arguments("triage_routing", bad)

    def section(platform="fortinet", queries=("system_status", "route_lookup"), addresses=(ADDRESS,)):
        return SimpleNamespace(egress={}, catalog_platform=lambda: platform, enabled_queries=queries,
                               read_inventory={"addresses": addresses})

    Proxy._authorize_tool("triage_routing", args, None, section())
    for changed in (section(platform="fortiadc"), section(queries=("system_status",)),
                    section(queries=("route_lookup",)), section(addresses=("198.51.100.21",))):
        with pytest.raises(proxy_module.PolicyScopeError):
            Proxy._authorize_tool("triage_routing", args, None, changed)
    proxy = Proxy()
    monkeypatch.setattr(proxy_module.time, "monotonic", lambda: 100.0)
    limit = {"requests": 30, "window_seconds": 60}
    proxy.rate_history["fg"] = deque([90.0] * 26)
    with pytest.raises(proxy_module.RateLimitError):
        proxy._consume_rate_limit("fg", limit, proxy_module.TRIAGE_READS["triage_routing"])
    proxy.rate_history["fg"] = deque([90.0] * 25)
    proxy._consume_rate_limit("fg", limit, proxy_module.TRIAGE_READS["triage_routing"])
    assert len(proxy.rate_history["fg"]) == 30
    assert proxy_module.TRIAGE_ROUTING_READS == t.PLANNED_READS == 5
    assert proxy_module.TRIAGE_READS["triage_health"] == 10
