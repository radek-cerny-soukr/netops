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
from netops_helper import triage_health as t

STATUS = "Version: FortiGate-60F v7.6.8,build3744,260115 (GA.M)\nVirtual domain configuration: disable\n"
CONSERVE = """memory conserve mode:                               off
total RAM:                                                  997 MB
memory used:                                                735 MB   73% of total RAM
memory freeable:                                            173 MB   17% of total RAM
memory used + freeable threshold extreme:                   947 MB   95% of total RAM
memory used threshold red:                                  877 MB   88% of total RAM
memory used threshold green:                                817 MB   82% of total RAM
"""
PERFORMANCE = """CPU states: 5% user 0% system 0% nice 95% idle 0% iowait 0% irq 0% softirq
CPU0 states: 0% user 0% system 0% nice 100% idle 0% iowait 0% irq 0% softirq
Memory: 1979848k total, 795716k used (40.2%), 750484k free (37.9%), 433648k freeable (21.9%)
Average sessions: 16 sessions in 1 minute, 15 sessions in 10 minutes, 15 sessions in 30 minutes
"""
SESSIONS = """misc info: session_count=128 setup_rate=0 exp_count=0 reflect_count=0 clash=0
      memory_tension_drop=0 ephemeral=0/0 removeable=0 extreme_low_mem=0
      npu_session_count=0
delete=0, flush=3, dev_down=0/0 ses_walkers=0
"""
HA_STANDALONE = "HA Health Status: OK\nModel: FortiGate-60F\nMode: standalone\nGroup ID: 0\n"
HA_AP = """HA Health Status: OK
Model: FortiGate-80F
Mode: HA A-P
Group Name: Branch1-HA
Configuration Status:
    FGT80FTK22023xxx(updated 1 seconds ago): in-sync
"""
HA_WARNING = """HA Health Status:
    WARNING: FG101FTK19xxxxx7 has hbdev down;
    WARNING: FG101FTK19xxxxx8 has hbdev down;
Model: FortiGate-101F
Mode: HA A-A
"""
SUM_A = "2b e9 81 38 c2 9d 4f db b7 0e 1f 49 42 c6 1e fb"
SUM_B = "89 1f 63 77 48 8a 30 ee 57 06 ca eb 71 e6 8e ad"
SUM_C = "d1 31 59 fc 0b 91 12 ca 92 69 62 d2 9f b7 a3 c3"


def checksum(second_all=SUM_B):
    def member(name, primary, value):
        return (f"================== {name} ==================\n\nis_manage_primary()={primary}, is_root_primary()={primary}\n"
                f"debugzone\nglobal: {SUM_A}\nroot: {SUM_C}\nall: {SUM_C}\n\n"
                f"checksum\nglobal: {SUM_A}\nroot: {SUM_C}\nall: {value}\n\n")
    return member("FG5H0XXXXXXXXXX0", 1, SUM_B) + member("FG5H0XXXXXXXXXX1", 0, second_all)


NTP = """synchronized: yes, ntpsync: enabled, server-mode: disabled
ipv4 server(198.51.100.11) 198.51.100.11 -- reachable(0xff) S:4 T:6 selected
server-version=4, stratum=3
"""
UPDATES = """FMWP Definitions
---------
Version: 23.00084 signed
Contract Expiry Date: Wed Jan 1 2031
Last Updated using manual update on Wed Sep 6 15:19:11 2023
Last Update Attempt: Wed Sep 6 15:40:08 2023
Result: No Updates

IP Geography DB
---------
Version: 3.00152
Contract Expiry Date: n/a
Last Updated using manual update on Thu Nov 17 17:52:00 2022
Last Update Attempt: Wed Nov 23 10:56:46 2022
Result: No Updates
"""
PHYSICAL = """== [onboard]
        ==[port1]
                mode: static
                ip: 0.0.0.0 0.0.0.0
                ipv6: ::/0
                status: down
                speed: n/a
                FEC: none
        ==[wan1]
                mode: static
                status: up
                speed: 1000Mbps (Duplex: full)
"""
SDWAN = """Health Check(server):
Seq(1): state(alive), packet-loss(0.000%) latency(15.247), jitter(5.231) sla_map=0x0
Seq(2): state(alive), packet-loss(0.000%) latency(13.621), jitter(6.905) sla_map=0x0
"""
SDWAN_DEAD = """Health Check(HUB):
Seq(13 Placeholder_MPLS_1): state(dead), packet-loss(100.000%), sla_map=0x0
"""
NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def outputs(**changes):
    values = {"system_status": STATUS, "conserve_state": CONSERVE, "performance": PERFORMANCE,
              "session_stats": SESSIONS, "ha_status": HA_STANDALONE, "ha_checksum": checksum(),
              "ntp_status": NTP, "autoupdate_versions": UPDATES, "physical_interfaces": PHYSICAL,
              "sdwan_health": SDWAN}
    values.update(changes)
    return values


def run(values, refused=()):
    calls = []

    def read(query):
        calls.append(query)
        if query in refused:
            return {"ok": False, "reason": refused[query] if isinstance(refused, dict) else "device_cli_error"}
        text = values[query]
        return {"ok": True, "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest()}

    ticks = iter(NOW + timedelta(seconds=n) for n in range(100))
    result = t.run(read, lambda: next(ticks))
    return result, calls


def ids(result):
    return [item["id"] for item in result["findings"]]


NTP_POOL = """HA primary: yes, HA primary ip: 192.0.2.250, management_vfid: 0 ha_direct=0, ha_mgmt_vfid=-1
synchronized: yes, ntpsync: enabled, server-mode: enabled

ipv4 server(ntp1.example.net) 192.0.2.63 -- reachable(0xff) S:2 T:588 
	server-version=4, stratum=2
ipv4 server(ntp2.example.net) 192.0.2.62 -- reachable(0xff) S:2 T:588 selected 
	server-version=4, stratum=2
ipv4 server(ntp2.example.net) 192.0.2.60 -- reachable(0xff) S:2 T:588 
ipv4 server(ntp1.example.net) 192.0.2.61 -- reachable(0xff) S:2 T:588 
ipv6 server(pool.example.net) 2001:db8::1 -- unreachable(0x00) S:2 T:588 
"""


def test_ntp_servers_with_the_same_name_are_told_apart_by_address():
    # measured on a FortiGate-80F test unit: ntp1/ntp2 each appear twice with different addresses
    servers = t.ntp_status(NTP_POOL)["servers"]
    assert [(item["server"], item["address"]) for item in servers] == [
        ("ntp1.example.net", "192.0.2.63"), ("ntp2.example.net", "192.0.2.62"), ("ntp2.example.net", "192.0.2.60"),
        ("ntp1.example.net", "192.0.2.61"), ("pool.example.net", "2001:db8::1")]
    assert len({item["address"] for item in servers}) == 5 and servers[4]["state"] == "unreachable"


def test_docs_samples_parse_into_the_contract_fields():
    assert t.conserve(CONSERVE) == {"memory_conserve_mode": "off", "used_percent": 73, "freeable_percent": 17,
                                    "extreme_percent": 95, "red_percent": 88, "green_percent": 82}
    assert t.performance(PERFORMANCE) == {"cpu_idle_percent": 95, "memory_used_percent": 40.2}
    assert t.session_stats(SESSIONS) == {"session_count": 128, "setup_rate": 0, "memory_tension_drop": 0,
                                         "extreme_low_mem": 0}
    assert t.ha_status(HA_WARNING) == {"mode": "HA A-A", "health_status": None, "warnings": [
        "WARNING: FG101FTK19xxxxx7 has hbdev down;", "WARNING: FG101FTK19xxxxx8 has hbdev down;"]}
    assert set(t.ha_checksum(checksum())["members"]) == {"FG5H0XXXXXXXXXX0", "FG5H0XXXXXXXXXX1"}
    assert t.ntp_status(NTP) == {"synchronized": "yes", "ntpsync": "enabled",
                                 "servers": [{"server": "198.51.100.11", "address": "198.51.100.11", "state": "reachable"}]}
    assert [(p["package"], p["contract_expiry"]) for p in t.autoupdate_versions(UPDATES)] == [
        ("FMWP Definitions", "Wed Jan 1 2031"), ("IP Geography DB", "n/a")]
    assert t.physical_interfaces(PHYSICAL) == [{"name": "port1", "status": "down", "speed": "n/a"},
                                               {"name": "wan1", "status": "up", "speed": "1000Mbps (Duplex: full)"}]
    assert t.sdwan_health(SDWAN_DEAD) == [{"health_check": "HUB", "seq": 13, "member": "Placeholder_MPLS_1",
                                           "state": "dead", "packet_loss": 100.0, "latency": None, "jitter": None}]


def test_clean_standalone_device_is_never_called_healthy():
    result, calls = run(outputs())
    assert result["verdict"] == "no_fault_in_checked_data"
    assert result["findings"] == []
    assert result["missing"] == [{"step": "ha_checksum", "reason": "not_applicable"}]
    assert "ha_checksum" not in calls and len(calls) == 9
    assert result["identity"] == {"product": "FortiGate-60F", "version": "7.6.8", "build": "3744"}
    assert set(result) >= {"chain", "findings", "hypotheses", "next_steps", "missing", "verdict", "checked"}
    assert "checks" not in result
    assert "healthy" not in json.dumps(result).lower()
    assert result["chain"]["links"]["physical"][0]["status"] == "down"


@pytest.mark.parametrize("change,rule", [
    ({"conserve_state": CONSERVE.replace("off", "on")}, "F-CONSERVE-ON"),
    ({"conserve_state": CONSERVE.replace("735 MB   73%", "880 MB   88%").replace("173 MB   17%", "50 MB   5%")}, "F-MEM-RED"),
    ({"conserve_state": CONSERVE.replace("173 MB   17%", "224 MB   22%")}, "F-MEM-EXTREME"),
    ({"ha_status": HA_WARNING, "ha_checksum": checksum()}, "F-HA-STATUS"),
    ({"ha_status": HA_AP.replace("HA Health Status: OK", "HA Health Status: WARNING"), "ha_checksum": checksum()}, "F-HA-STATUS"),
    ({"ha_status": HA_AP.replace("HA Health Status: OK\n", "HA Health Status: OK\n    WARNING: FGT80FTK22023xxx has hbdev down;\n"), "ha_checksum": checksum()}, "F-HA-STATUS"),
    ({"ha_status": HA_AP, "ha_checksum": checksum(SUM_C)}, "F-HA-CHECKSUM"),
    ({"ntp_status": NTP.replace("synchronized: yes", "synchronized: no")}, "F-NTP-UNSYNC"),
    ({"autoupdate_versions": UPDATES.replace("Wed Jan 1 2031", "Thu Oct 30 2026")}, "F-UPDATE-EXPIRED"),
    ({"sdwan_health": SDWAN_DEAD}, "F-SDWAN-DEAD"),
])
def test_each_documented_rule_reports_a_sourced_fact(change, rule):
    result, _ = run(outputs(**change))
    assert ids(result) == [rule]
    assert result["verdict"] == "fault_found"
    source = result["findings"][0]["sources"][0]
    assert source["call"] == "triage_health" and len(source["content_sha256"]) == 64
    assert source["captured_at"].endswith("Z") and result["findings"][0]["layer"] == "runtime"


def test_thresholds_come_from_the_device_not_from_defaults():
    lowered = CONSERVE.replace("877 MB   88%", "700 MB   70%")
    result, _ = run(outputs(conserve_state=lowered))
    assert ids(result) == ["F-MEM-RED"]
    raised = (CONSERVE.replace("735 MB   73%", "880 MB   88%").replace("877 MB   88%", "940 MB   94%")
              .replace("173 MB   17%", "50 MB   5%"))
    assert ids(run(outputs(conserve_state=raised))[0]) == []


def test_boundaries_of_the_memory_rules():
    at_red = CONSERVE.replace("735 MB   73%", "877 MB   88%")
    below_red = CONSERVE.replace("735 MB   73%", "867 MB   87%")
    assert "F-MEM-RED" in ids(run(outputs(conserve_state=at_red))[0])
    assert "F-MEM-RED" not in ids(run(outputs(conserve_state=below_red))[0])
    at_extreme = CONSERVE.replace("173 MB   17%", "214 MB   22%")
    below_extreme = CONSERVE.replace("173 MB   17%", "204 MB   21%")
    assert "F-MEM-EXTREME" in ids(run(outputs(conserve_state=at_extreme))[0])
    assert "F-MEM-EXTREME" not in ids(run(outputs(conserve_state=below_extreme))[0])


def test_session_drop_counters_are_context_only():
    busy = SESSIONS.replace("memory_tension_drop=0", "memory_tension_drop=7").replace("extreme_low_mem=0", "extreme_low_mem=3")
    result, _ = run(outputs(session_stats=busy))
    assert result["findings"] == [] and result["verdict"] == "no_fault_in_checked_data"
    assert result["chain"]["sessions"]["memory_tension_drop"] == 7


def test_contract_expiry_today_and_na_are_not_findings():
    today = UPDATES.replace("Wed Jan 1 2031", "Sat Oct 31 2026")
    assert ids(run(outputs(autoupdate_versions=today))[0]) == []


def test_ha_cluster_reads_checksum_and_matching_sums_are_no_finding():
    result, calls = run(outputs(ha_status=HA_AP))
    assert "ha_checksum" in calls and result["missing"] == []
    assert result["verdict"] == "no_fault_in_checked_data"


@pytest.mark.parametrize("step", sorted(t.REQUIRED - {"system_status"}))
def test_a_refused_required_step_is_incomplete_never_clean(step):
    result, _ = run(outputs(), refused={step: "device_cli_error"})
    assert result["verdict"] == "incomplete"
    assert {"step": step, "reason": "device_cli_error"} in result["missing"]


def test_refusal_is_never_read_as_zero_or_ok_and_findings_survive():
    result, _ = run(outputs(conserve_state=CONSERVE.replace("off", "on")),
                    refused={"ha_status": "permission_denied", "ntp_status": "timeout"})
    assert result["verdict"] == "incomplete"
    assert ids(result) == ["F-CONSERVE-ON"]
    assert result["chain"]["ha"]["health_status"] is None and result["chain"]["ntp"] is None
    assert {"step": "ha_checksum", "reason": "permission_denied"} in result["missing"]


@pytest.mark.parametrize("query,text", [
    ("conserve_state", CONSERVE + "memory surprise: 1\n"),
    ("conserve_state", CONSERVE.replace("73% of total RAM", "lots")),
    ("performance", "CPU usage high\n"),
    ("session_stats", "misc info: session_count=1\n"),
    ("ha_status", "Mode: standalone\n"),
    ("ntp_status", "synchronized: maybe\n"),
    ("autoupdate_versions", UPDATES.replace("Wed Jan 1 2031", "someday")),
    ("physical_interfaces", "==[port1]\n mode: static\n"),
    ("sdwan_health", "Seq(1): state(alive)\n"),
    ("sdwan_health", "Health Check(x):\nSeq(1): state(unknown)\n"),
])
def test_unknown_shape_is_unparsed_and_incomplete(query, text):
    result, _ = run(outputs(**{query: text}))
    assert {"step": query, "reason": "unparsed"} in result["missing"]
    assert result["verdict"] == "incomplete"


def test_empty_sdwan_is_not_applicable_but_empty_required_step_is_not():
    result, _ = run(outputs(sdwan_health="\n"))
    assert result["missing"][-1] == {"step": "sdwan_health", "reason": "not_applicable"}
    assert result["verdict"] == "no_fault_in_checked_data"
    result, _ = run(outputs(ntp_status=""))
    assert {"step": "ntp_status", "reason": "empty"} in result["missing"] and result["verdict"] == "incomplete"


def test_cluster_checksum_with_one_member_is_unparsed():
    single = checksum()[:checksum().index("================== FG5H0XXXXXXXXXX1")]
    result, _ = run(outputs(ha_status=HA_AP, ha_checksum=single))
    assert {"step": "ha_checksum", "reason": "unparsed"} in result["missing"]


@pytest.mark.parametrize("status", [
    "Version: FortiGate-80F v8.0.2,build0252,260928 (GA.F)\n",
    "Version: FortiGate-80F v8.0.1,build0251,260928 (GA.F)\n",
    "Version: FortiGate-60F v7.6.8,build3745,260115 (GA.M)\n",
    "Version: FortiGate-VM64 v7.6.8,build3744,260115 (GA.M)\n",
    "no identity\n",
])
def test_unqualified_identity_stops_before_any_other_read(status):
    calls = []

    def read(query):
        calls.append(query)
        return {"ok": True, "text": status, "content_sha256": "0" * 64}

    with pytest.raises(t.UnsupportedPlatform, match="config_platform_not_supported"):
        t.run(read, lambda: NOW)
    assert calls == ["system_status"]


def test_failed_identity_read_is_not_supported():
    with pytest.raises(t.UnsupportedPlatform, match="config_platform_not_supported"):
        t.run(lambda query: {"ok": False, "reason": "timeout"}, lambda: NOW)


def test_next_steps_are_catalog_reads_only():
    result, _ = run(outputs(conserve_state=CONSERVE.replace("off", "on")))
    assert result["next_steps"] == [{"tool": "ssh_read", "arguments": {"platform": "fortinet", "query": "hardware_memory"},
                                     "why": "memory detail behind conserve mode"}]


COMMANDS = {
    "get system status": "system_status", "diagnose hardware sysinfo conserve": "conserve_state",
    "get system performance status": "performance", "diagnose sys session stat": "session_stats",
    "get system ha status": "ha_status", "diagnose sys ha checksum cluster": "ha_checksum",
    "diagnose sys ntp status": "ntp_status", "diagnose autoupdate versions": "autoupdate_versions",
    "get system interface physical": "physical_interfaces", "diagnose sys sdwan health-check": "sdwan_health",
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


def test_engine_reads_each_enabled_query_once_and_audits_every_read(audit_log, monkeypatch):
    sent = []
    values = outputs()

    def device(auth, platform, command, **_):
        sent.append(command)
        return 0, values[COMMANDS[command]]

    monkeypatch.setattr(engine, "read_from_device", device)
    result = engine.triage_health(_enrolled(*COMMANDS.values()))
    assert result["ok"] is True and result["target"] == "wire-test"
    assert result["verdict"] == "no_fault_in_checked_data"
    assert sent == [c for c in COMMANDS if c != "diagnose sys ha checksum cluster"]
    records = [json.loads(line) for line in audit_log.read_text().splitlines()]
    assert [r["event"] for r in records].count("triage_health_read") == 18
    assert [r["event"] for r in records][0] == "triage_health" and records[-1]["event"] == "triage_health"
    assert {r.get("query") for r in records if r["event"] == "triage_health_read"} == set(COMMANDS.values()) - {"ha_checksum"}
    assert "untrusted_device_output" not in result


def test_engine_maps_policy_refusal_and_device_refusal_to_missing(audit_log, monkeypatch):
    values = outputs()

    def device(auth, platform, command, **_):
        if command == "diagnose sys ntp status":
            return 0, "Command fail. Return code -37"
        return 0, values[COMMANDS[command]]

    monkeypatch.setattr(engine, "read_from_device", device)
    enabled = [q for q in COMMANDS.values() if q != "session_stats"]
    result = engine.triage_health(_enrolled(*enabled))
    assert {"step": "session_stats", "reason": "permission_denied"} in result["missing"]
    assert {"step": "ntp_status", "reason": "device_cli_error"} in result["missing"]
    assert result["verdict"] == "incomplete"
    assert result["ok"] is True and "error_code" not in result and "failed_step" not in result


def test_engine_refuses_other_platforms_before_device_contact(audit_log, monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    with pytest.raises(ValueError, match="unsupported_platform"):
        engine.triage_health(_target("fortiadc", "system_status"))


def test_engine_redacts_secrets_before_parsing(audit_log, monkeypatch):
    values = outputs()
    seen = {}

    def device(auth, platform, command, **_):
        text = values[COMMANDS[command]]
        if command == "get system ha status":
            text = text.replace("Model: FortiGate-60F", "Model: " + auth.secret)
        return 0, text

    monkeypatch.setattr(engine, "read_from_device", device)
    original = t.ha_status
    monkeypatch.setattr(t, "PARSERS", {**t.PARSERS, "ha_status": lambda text: seen.setdefault("text", text) and original(text)})
    target = _enrolled(*COMMANDS.values())
    engine.triage_health(target)
    assert target.secret not in seen["text"]


def test_proxy_accepts_only_the_target_and_charges_the_whole_plan(monkeypatch):
    Proxy = proxy_module.Proxy
    assert Proxy._validate_tool_arguments("triage_health", {"target": "fg"}) == {"target": "fg"}
    with pytest.raises(proxy_module.ToolArgumentsError):
        Proxy._validate_tool_arguments("triage_health", {"target": "fg", "query": "x"})
    from types import SimpleNamespace
    section = SimpleNamespace(egress={}, catalog_platform=lambda: "fortinet", enabled_queries=("system_status",),
                              read_inventory={})
    Proxy._authorize_tool("triage_health", {"target": "fg"}, None, section)
    for changed in (SimpleNamespace(egress={}, catalog_platform=lambda: "fortiadc", enabled_queries=("system_status",)),
                    SimpleNamespace(egress={}, catalog_platform=lambda: "fortinet", enabled_queries=("performance",))):
        with pytest.raises(proxy_module.PolicyScopeError):
            Proxy._authorize_tool("triage_health", {"target": "fg"}, None, changed)
    proxy = Proxy()
    monkeypatch.setattr(proxy_module.time, "monotonic", lambda: 100.0)
    limit = {"requests": 30, "window_seconds": 60}
    proxy.rate_history["fg"] = deque([90.0] * 21)
    with pytest.raises(proxy_module.RateLimitError):
        proxy._consume_rate_limit("fg", limit, proxy_module.TRIAGE_HEALTH_READS)
    assert len(proxy.rate_history["fg"]) == 21
    proxy.rate_history["fg"] = deque([90.0] * 20)
    proxy._consume_rate_limit("fg", limit, proxy_module.TRIAGE_HEALTH_READS)
    assert len(proxy.rate_history["fg"]) == 30
    assert proxy_module.TRIAGE_HEALTH_READS == t.PLANNED_READS == 10


@pytest.mark.parametrize("mode", ["Standalone", "STANDALONE"])
def test_standalone_mode_is_recognised_in_any_letter_case(mode):
    result, calls = run(outputs(ha_status=HA_STANDALONE.replace("Mode: standalone", "Mode: " + mode)))
    assert "ha_checksum" not in calls
    assert result["missing"] == [{"step": "ha_checksum", "reason": "not_applicable"}]
    assert result["verdict"] == "no_fault_in_checked_data"


@pytest.mark.parametrize("text", [
    "SD-WAN health monitor is not running.\n\n",
    "SD-WAN daemon is not running.\n\n",
])
def test_sdwan_monitor_not_running_is_not_applicable(text):
    result, calls = run(outputs(sdwan_health=text))
    assert calls[-1] == "sdwan_health"
    assert result["missing"][-1] == {"step": "sdwan_health", "reason": "not_applicable"}
    assert "sdwan_health" not in result["checked"]
    assert result["verdict"] == "no_fault_in_checked_data"


@pytest.mark.parametrize("text", [
    "SD-WAN health monitor is not running.\nHealth Check(HUB):\n",
    "SD-WAN health monitor is not running. Restarting\n",
    "Note: SD-WAN health monitor is not running.\n",
    "SD-WAN daemon is not running.\nHealth Check(HUB):\n",
    "SD-WAN daemon is not running. Restarting\n",
    "Note: SD-WAN daemon is not running.\n",
])
def test_not_running_text_inside_other_output_stays_unparsed(text):
    result, _ = run(outputs(sdwan_health=text))
    assert {"step": "sdwan_health", "reason": "unparsed"} in result["missing"]
    assert result["verdict"] == "incomplete"


def test_measured_fortigate_80f_802_identity_proceeds_past_identity():
    result, _ = run(outputs(system_status="Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)\nVirtual domain configuration: disable\n", ha_status=HA_AP, ha_checksum=checksum(SUM_B)))
    assert result["identity"] == {"product": "FortiGate-80F", "version": "8.0.2", "build": "0251"}
