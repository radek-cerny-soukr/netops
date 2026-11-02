"""Contracts of the read-only FortiADC server load-balancing triage.

The runtime texts below are the measured FortiADC 7.6.7 build 0676 outputs of
slb_load (dc249947), slb_vs_stat VS_APP_HTTP (122247a3) and tls_handshake_stats
(61754705); every other device text is synthetic and named as such.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from types import SimpleNamespace
from unittest import mock

import pytest

from netops_helper import engine, triage_slb as rules
from netops_helper import inventory, proxy

SLB_LOAD = (
    'vdom name is  root\n'
    '\tvirtual-server VS_APP_HTTP\n'
    '\t\treal-server POOL_APP\n'
    '\t\tid:1, status 1, weight 0\n'
    '\t\tid:2, status 1, weight 0\n'
    '\tvirtual-server LAB_VS_HTTPS\n'
    '\t\treal-server POOL_APP\n'
    '\t\tid:1, status 1, weight 0\n'
    '\t\tid:2, status 1, weight 0\n'
    '\tvirtual-server LAB_VS_SMTP\n'
    '\t\treal-server LAB_POOL_SMTP\n'
    '\t\tid:1, status 1, weight 0\n'
    '\t\tid:2, status 1, weight 0\n'
    '\tvirtual-server LAB_VS_DNS\n'
    '\t\treal-server LAB_POOL_DNS\n'
    '\t\tid:1, status 1, weight 0\n'
    '\t\tid:2, status 1, weight 0'
)
VS_STAT = (
    'vdom name is root\n'
    '\tvirtual-server: VS_APP_HTTP, availability:HEALTHY\n'
    '\t\tAPP Response: 0\n'
    '\t\tClient RTT: 1\n'
    '\t\tConcurrent Connections: 0\n'
    '\t\tInbound Throughput: 0\n'
    '\t\tOutbound Throughput: 0\n'
    '\t\tRequests: 0\n'
    '\t\tServer RTT: 1\n'
    '\t\treal-server-pool: POOL_APP\n'
    '\t\tid:1, hc_state: UP, last-state-change-time: 2026-10-30 00:48:28\n'
    '\t\t\tAPP Response: 0\n'
    '\t\t\tConcurrent Connections: 0\n'
    '\t\t\tInbound Throughput: 0\n'
    '\t\t\tOutbound Throughput: 0\n'
    '\t\t\tRequests: 0\n'
    '\t\t\tServer RTT: 1\n'
    '\t\tid:2, hc_state: UP, last-state-change-time: 2026-10-30 00:37:05\n'
    '\t\t\tAPP Response: 0\n'
    '\t\t\tConcurrent Connections: 0\n'
    '\t\t\tInbound Throughput: 0\n'
    '\t\t\tOutbound Throughput: 0\n'
    '\t\t\tRequests: 0\n'
    '\t\t\tServer RTT: 1'
)
TLS_STATS = (
    'execute ssl-handshake-n-record-statistics show virtual-server LAB \x08_VS_HTTPS\n'
    'VS client-side SSL statistics:\n'
    '\t# of succeeded HANDSHAKEs: 399, average latency 0(us)\n'
    '\t# of failed HANDSHAKEs: 1( 0%)\n'
    '\t# of SSL init: 400, # of failed SSL init: 0, # of SSL close: 400, # of SSL free: 400\n'
    '\t# of hw failure: 0\n'
    '\thandshake: # of hw req: 0, # of hw done: 0\n'
    '\tread: # of hw req: 0, # of hw done: 0\n'
    '\twrite: # of hw req: 0, # of hw done: 0\n'
    '\t# of read errors happened: 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 1000 is 862758(100%)\n'
    '\t# of processed SSL READ record with size less than 2000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 3000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 4000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size NO less than 4000 is 0( 0%)\n'
    '\t# of write errors happened: 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 1000 is 862758(100%)\n'
    '\t# of processed SSL WRITE record with size less than 2000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 3000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 4000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size NO less than 4000 is 0( 0%)\n'
    '\t# of ADC initiated renegotiates success: 0\n'
    '\t# of ADC initiated renegotiates fail: 0\n'
    '\t# of PEER initiated renegotiates success: 0\n'
    '\t# of PEER initiated renegotiates fail: 0\n'
    'VS server-side SSL statistics for server with id 1:\n'
    '\t# of succeeded HANDSHAKEs: 0, average latency 0(us)\n'
    '\t# of failed HANDSHAKEs: 0( 0%)\n'
    '\t# of SSL init: 0, # of failed SSL init: 0, # of SSL close: 0, # of SSL free: 0\n'
    '\t# of hw failure: 0\n'
    '\thandshake: # of hw req: 0, # of hw done: 0\n'
    '\tread: # of hw req: 0, # of hw done: 0\n'
    '\twrite: # of hw req: 0, # of hw done: 0\n'
    '\t# of read errors happened: 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 1000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 2000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 3000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 4000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size NO less than 4000 is 0( 0%)\n'
    '\t# of write errors happened: 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 1000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 2000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 3000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 4000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size NO less than 4000 is 0( 0%)\n'
    '\t# of ADC initiated renegotiates success: 0\n'
    '\t# of ADC initiated renegotiates fail: 0\n'
    '\t# of PEER initiated renegotiates success: 0\n'
    '\t# of PEER initiated renegotiates fail: 0\n'
    'VS server-side SSL statistics for server with id 2:\n'
    '\t# of succeeded HANDSHAKEs: 0, average latency 0(us)\n'
    '\t# of failed HANDSHAKEs: 0( 0%)\n'
    '\t# of SSL init: 0, # of failed SSL init: 0, # of SSL close: 0, # of SSL free: 0\n'
    '\t# of hw failure: 0\n'
    '\thandshake: # of hw req: 0, # of hw done: 0\n'
    '\tread: # of hw req: 0, # of hw done: 0\n'
    '\twrite: # of hw req: 0, # of hw done: 0\n'
    '\t# of read errors happened: 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 1000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 2000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 3000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size less than 4000 is 0( 0%)\n'
    '\t# of processed SSL READ record with size NO less than 4000 is 0( 0%)\n'
    '\t# of write errors happened: 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 1000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 2000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 3000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size less than 4000 is 0( 0%)\n'
    '\t# of processed SSL WRITE record with size NO less than 4000 is 0( 0%)\n'
    '\t# of ADC initiated renegotiates success: 0\n'
    '\t# of ADC initiated renegotiates fail: 0\n'
    '\t# of PEER initiated renegotiates success: 0\n'
    '\t# of PEER initiated renegotiates fail: 0'
)

DOS_ACCESS = "[vs: VS_APP_HTTP]: Total access alloc node = 0\n================Only show 150 items================"
DOS_ALLOC = "[vs: VS_APP_HTTP]: Alloced num 0\n================Only show 150 items================"
STATUS = "Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"
VS = "VS_APP_HTTP"
POOL = "POOL_APP"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def vs_config(status="enable", extra=""):
    return ("config load-balance virtual-server\n  edit VS_APP_HTTP\n    set status %s\n"
            "    set type l7-load-balance\n    set load-balance-pool POOL_APP\n%s"
            "    config content-rewriting\n    end\n  next\nend\n" % (status, extra))


def pool_config(statuses=("enable", "enable"), checks="    set health-check-ctrl enable\n    set health-check-list HC_HTTP_APP\n"):
    members = "".join(
        "      edit %d\n        set real-server RS_%d\n        set pool_member_service_port 80\n"
        "        set status %s\n      next\n" % (index, index, status)
        for index, status in enumerate(statuses, 1))
    return ("config load-balance pool\n  edit POOL_APP\n%s    config pool_member\n%s    end\n  next\nend\n"
            % (checks, members))


HC = "config system health-check\n  edit HC_HTTP_APP\n    set type http\n    set port 80\n    set interval 10\n  next\nend\n"
PERF = "CPU usage: 2%\nMemory usage: 41%\nConcurrent sessions: 0\n"


def vs_stat(states=("UP", "UP"), availability="HEALTHY"):
    """Synthetic DOWN variants are derived from the measured text by state substitution only."""
    text = VS_STAT.replace("availability:HEALTHY", "availability:" + availability)
    parts = text.split("hc_state: UP")
    assert len(parts) == 3
    return parts[0] + "hc_state: " + states[0] + parts[1] + "hc_state: " + states[1] + parts[2]


class Auth:
    alias = "adc"
    port = 22
    login = "reader"
    legacy_ssh = None
    secrets = ()
    ssh_platform = "fortiadc"

    def __init__(self, allow_icmp=True, **inventory_changes):
        self.egress = SimpleNamespace(allow_icmp=allow_icmp)
        self.read_inventory = {"config_access": ("read",), "adc_virtual_servers": (VS,), "adc_vdoms": ("root",),
                               "adc_health_checks": ("HC_HTTP_APP",),
                               "diagnostic_recipes": ("ping", "health_check_verify"), **inventory_changes}

    def require_tcp_port(self, port):
        assert port == 22


class Device:
    def __init__(self, configs=None, queries=None, status=STATUS):
        self.configs = {"load-balance virtual-server " + VS: vs_config(), "load-balance pool " + POOL: pool_config(),
                        "system health-check HC_HTTP_APP": HC, **(configs or {})}
        self.queries = {"slb_vs_stat": VS_STAT, "slb_load": SLB_LOAD, "system_performance": PERF, **(queries or {})}
        self.status = status
        self.calls = []

    def read_from_device(self, auth, platform, command, **kwargs):
        self.calls.append(("identity", command))
        if isinstance(self.status, Exception):
            raise self.status
        return 0, self.status

    def config_read(self, auth, platform, section, **kwargs):
        self.calls.append(("config_read", section, kwargs["redaction"], kwargs["include_defaults"]))
        value = self.configs[section]
        if isinstance(value, Exception):
            raise value
        return {"untrusted_device_output": value, "content_sha256": sha(value), "next_offset": None}

    def ssh_read(self, auth, platform, query, parameters, offset, max_bytes):
        self.calls.append(("ssh_read", query, parameters))
        value = self.queries[query]
        if isinstance(value, dict):
            return value
        if isinstance(value, Exception):
            raise value
        return {"ok": True, "untrusted_device_output": value, "content_sha256": sha(value), "next_offset": None}


def run(device, auth=None, virtual_server=VS, vdom="root"):
    with mock.patch.object(engine, "record", lambda *args, **kwargs: None), \
            mock.patch.object(engine, "read_from_device", device.read_from_device), \
            mock.patch.object(engine, "config_read", device.config_read), \
            mock.patch.object(engine, "ssh_read", device.ssh_read):
        return engine.triage_slb(auth or Auth(), virtual_server, vdom)


def ids(result):
    return [finding["id"] for finding in result["findings"]]


def test_measured_texts_are_the_pinned_captures():
    assert sha(SLB_LOAD).startswith("dc249947")
    assert sha(VS_STAT).startswith("122247a3")
    assert sha(TLS_STATS).startswith("61754705")


def test_measured_vs_stat_is_read_literally():
    parsed = rules.parse_vs_stat(VS_STAT, VS, "root")
    assert parsed["availability"] == "HEALTHY"
    assert parsed["counters"]["Concurrent Connections"] == 0 and parsed["counters"]["Client RTT"] == 1
    assert [pool["name"] for pool in parsed["pools"]] == [POOL]
    assert [(m["id"], m["hc_state"], m["last_state_change"]) for m in parsed["pools"][0]["members"]] == [
        (1, "UP", "2026-10-30 00:48:28"), (2, "UP", "2026-10-30 00:37:05")]
    assert parsed["pools"][0]["members"][1]["counters"]["Server RTT"] == 1


def test_measured_slb_load_selects_only_the_asked_virtual_server():
    assert rules.parse_slb_load(SLB_LOAD, VS) == {"present": True, "pools": [{"name": POOL, "members": [
        {"id": 1, "status": 1, "weight": 0}, {"id": 2, "status": 1, "weight": 0}]}]}
    assert rules.parse_slb_load(SLB_LOAD, "VS_OTHER") == {"present": False, "pools": []}


def test_measured_tls_and_dos_counters_are_literal():
    parsed = rules.parse_tls_stats(TLS_STATS)
    assert (parsed["client"]["succeeded"], parsed["client"]["failed"]) == (399, 1)
    assert [side["server_id"] for side in parsed["servers"]] == [1, 2]
    assert rules.parse_dos(DOS_ACCESS, VS) == {"metric": "Total access alloc node", "value": 0}
    assert rules.parse_dos(DOS_ALLOC, VS) == {"metric": "Alloced num", "value": 0}


@pytest.mark.parametrize("parser,text", [
    (lambda t: rules.parse_vs_stat(t, VS, "root"), VS_STAT.replace("hc_state: UP", "hc_state: up", 1)),
    (lambda t: rules.parse_vs_stat(t, VS, "root"), VS_STAT + "\n\t\tid:3, state DOWN"),
    (lambda t: rules.parse_vs_stat(t, VS, "root"), VS_STAT.replace("vdom name is root", "vdom name is other")),
    (lambda t: rules.parse_vs_stat(t, VS, "root"), VS_STAT.replace("virtual-server: VS_APP_HTTP", "virtual-server: VS_X")),
    (lambda t: rules.parse_vs_stat(t, VS, "root"), ""),
    (lambda t: rules.parse_slb_load(t, VS), SLB_LOAD + "\n\t\tid:3, status DOWN"),
    (lambda t: rules.parse_slb_load(t, VS), SLB_LOAD.replace("vdom name is", "domain")),
    (lambda t: rules.parse_tls_stats(t), TLS_STATS.replace("# of failed HANDSHAKEs", "# of bad HANDSHAKEs")),
    (lambda t: rules.parse_dos(t, VS), DOS_ALLOC.replace("Alloced num", "Blocked num")),
    (lambda t: rules.parse_dos(t, VS), DOS_ALLOC.replace("VS_APP_HTTP", "VS_X")),
    (lambda t: rules.virtual_server_config(t, VS), vs_config().replace("    set status enable\n", "")),
    (lambda t: rules.virtual_server_config(t, VS), vs_config().replace("edit VS_APP_HTTP", "edit VS_X")),
    (lambda t: rules.virtual_server_config(t, VS), vs_config()[:-4]),
    (lambda t: rules.pool_config(t, POOL), pool_config().replace("      edit 1", "      edit one")),
    (lambda t: rules.pool_config(t, POOL), pool_config().replace("set real-server RS_1", 'set real-server "RS_1')),
    (lambda t: rules.pool_config(t, POOL), pool_config().replace("config load-balance pool", "config load-balance real-server")),
    (lambda t: rules.health_check_config(t, "HC_HTTP_APP"), HC.replace("set port 80", "set port 80 81")),
    (lambda t: rules.parse_key_values(t), "CPU usage 2%"),
])
def test_unknown_shapes_are_refused_not_guessed(parser, text):
    with pytest.raises(rules.TriageParseError):
        parser(text)


def test_measured_healthy_chain_reports_no_fault_only_for_checked_data():
    device = Device()
    result = run(device)
    assert result["verdict"] == "no_fault_in_checked_data"
    assert result["findings"] == [] and result["missing"] == [] and result["next_steps"] == []
    assert result["checked"] == ["health_check_config:HC_HTTP_APP", "pool_config", "slb_load", "slb_vs_stat",
                                 "system_performance", "vs_config"]
    assert result["identity"] == {"product": "FortiADC-KVM", "version": "7.6.7", "build": "0676"}
    assert [m["runtime"]["hc_state"] for m in result["chain"]["members"]] == ["UP", "UP"]
    assert "healthy" not in json.dumps({k: v for k, v in result.items() if k != "chain"}).casefold()
    assert device.calls[0] == ("identity", "get system status")
    assert [call[:2] for call in device.calls[1:]] == [
        ("config_read", "load-balance virtual-server VS_APP_HTTP"), ("config_read", "load-balance pool POOL_APP"),
        ("config_read", "system health-check HC_HTTP_APP"), ("ssh_read", "slb_vs_stat"), ("ssh_read", "slb_load"),
        ("ssh_read", "system_performance")]
    assert all(call[2:] == ("full", True) for call in device.calls if call[0] == "config_read")
    assert device.calls[4][2] == {"vdom": "root", "virtual_server": VS}


def test_synthetic_member_down_is_a_sourced_runtime_fault_with_next_steps():
    device = Device(queries={"slb_vs_stat": vs_stat(("UP", "DOWN"))})
    result = run(device)
    assert result["verdict"] == "fault_found"
    assert ids(result) == ["F-MEMBER-DOWN"]
    finding = result["findings"][0]
    assert finding["object"] == "POOL_APP id 2" and finding["layer"] == "runtime"
    assert "hc_state: DOWN" in finding["fact"] and "2026-10-30 00:37:05" in finding["fact"] and "HC_HTTP_APP" in finding["fact"]
    assert finding["fact"].startswith("real-server RS_2, hc_state: DOWN")
    assert {source["content_sha256"] for source in finding["sources"]} == {
        sha(pool_config()), sha(vs_stat(("UP", "DOWN")))}
    assert [step["arguments"]["recipe"] for step in result["next_steps"]] == ["health_check_verify", "ping"]
    assert result["next_steps"][0]["arguments"]["health_check"] == "HC_HTTP_APP"
    assert "RS_2" in result["next_steps"][0]["why"]
    assert result["hypotheses"][0]["based_on"] == ["F-MEMBER-DOWN"]


@pytest.mark.parametrize(("auth", "recipes"), [
    (Auth(allow_icmp=False), ["health_check_verify"]),
    (Auth(diagnostic_recipes=("ping",)), ["ping"]),
    (Auth(allow_icmp=False, diagnostic_recipes=("ping",)), []),
    (Auth(adc_health_checks=()), ["ping"]),
])
def test_next_steps_only_name_diagnostics_the_target_permits(auth, recipes):
    result = run(Device(queries={"slb_vs_stat": vs_stat(("UP", "DOWN"))}), auth)
    assert ids(result) == ["F-MEMBER-DOWN"]
    assert [step["arguments"]["recipe"] for step in result["next_steps"]] == recipes


def test_synthetic_all_down_and_availability_are_reported_literally():
    result = run(Device(queries={"slb_vs_stat": vs_stat(("DOWN", "DOWN"), "UNAVAILABLE")}))
    assert result["verdict"] == "fault_found"
    assert ids(result) == ["F-VS-AVAIL", "F-MEMBER-DOWN", "F-MEMBER-DOWN", "F-POOL-ALL-DOWN"]
    assert result["findings"][0]["fact"] == "availability:UNAVAILABLE"


def test_config_rules_disabled_vs_member_and_missing_health_check():
    result = run(Device(configs={"load-balance virtual-server " + VS: vs_config("disable"),
                                 "load-balance pool " + POOL: pool_config(("enable", "disable"), "")}))
    assert ids(result) == ["F-VS-DISABLED", "F-MEMBER-DISABLED", "F-NO-HC"]
    assert result["verdict"] == "fault_found"


def test_member_known_only_to_one_side_is_a_mismatch():
    result = run(Device(configs={"load-balance pool " + POOL: pool_config(("enable", "enable", "enable"))}))
    assert ids(result) == ["F-MISMATCH", "F-MISMATCH"]
    assert result["verdict"] == "fault_found"


def test_tls_dos_and_waf_steps_run_only_when_the_vs_references_them():
    extra = "    set client-ssl-profile SSL_APP\n    set waf-profile WAF_APP\n    set dos-profile DOS_APP\n"
    device = Device(configs={"load-balance virtual-server " + VS: vs_config(extra=extra),
                             "load-balance client-ssl-profile SSL_APP": "config load-balance client-ssl-profile\n  edit SSL_APP\n  next\nend\n",
                             "security waf profile WAF_APP": "config security waf profile\n  edit WAF_APP\n  next\nend\n"},
                    queries={"tls_handshake_stats": TLS_STATS, "dos_access_limit": DOS_ACCESS,
                             "dos_conn_limit": DOS_ALLOC, "dos_req_limit": DOS_ALLOC,
                             "waf_signature_status": "Signature version: 1.00042\nLast update: never\n"})
    result = run(device)
    assert ids(result) == ["F-TLS-FAIL", "F-DOS", "F-DOS", "F-DOS", "F-WAF", "F-WAF"]
    assert result["findings"][0]["fact"] == "client-side failed HANDSHAKEs: 1, succeeded: 399"
    assert result["verdict"] == "fault_found"
    assert ("config_read", "load-balance client-ssl-profile SSL_APP", "full", False) in device.calls
    plain = Device()
    run(plain)
    assert not {call[1] for call in plain.calls} & {"tls_handshake_stats", "dos_access_limit", "waf_signature_status"}


@pytest.mark.parametrize("failure,reason", [
    ({"ok": False, "error_code": "device_cli_error", "error": "command refused -284"}, "device_cli_error"),
    ({"ok": False, "error_code": "permission_denied", "error": "denied"}, "permission_denied"),
    (TimeoutError("timed out"), "timeout"),
    ({"ok": True, "untrusted_device_output": "", "content_sha256": sha(""), "next_offset": None}, "empty"),
    ({"ok": False, "error_code": "empty", "error": "no output"}, "empty"),
    ({"ok": True, "untrusted_device_output": "x", "content_sha256": sha("x"), "next_offset": 1}, "truncated"),
    ("CPU usage 2%", "unparsed"),
])
def test_a_refused_step_is_missing_never_zero_and_the_rest_still_runs(failure, reason):
    device = Device(queries={"system_performance": failure})
    result = run(device)
    assert result["missing"][0]["step"] == "system_performance" and result["missing"][0]["reason"] == reason
    assert result["chain"]["resources"]["runtime"] is None
    assert result["verdict"] == "incomplete"
    assert "system_performance" not in result["checked"]


def test_missing_required_step_keeps_findings_but_is_incomplete():
    device = Device(queries={"slb_vs_stat": {"ok": False, "error_code": "device_cli_error", "error": "-284"}})
    device.configs["load-balance virtual-server " + VS] = vs_config("disable")
    result = run(device)
    assert ids(result) == ["F-VS-DISABLED"]
    assert result["verdict"] == "incomplete"
    assert [m["runtime"] for m in result["chain"]["members"]] == [None, None]


def test_unreadable_vs_config_skips_pool_as_not_applicable():
    result = run(Device(configs={"load-balance virtual-server " + VS: ValueError("config access is not enabled")}))
    assert [(m["step"], m["reason"]) for m in result["missing"]] == [
        ("vs_config", "unsupported"), ("pool_config", "not_applicable")]
    assert result["verdict"] == "incomplete"


def test_unparsed_configuration_is_missing_and_stops_its_dependants():
    device = Device(configs={"load-balance pool " + POOL: pool_config().replace("      edit 2", "      edit two")})
    result = run(device)
    assert [(m["step"], m["reason"]) for m in result["missing"]] == [("pool_config", "unparsed")]
    assert result["chain"]["pool"]["config"] is None and result["chain"]["members"] == []
    assert not any(call[1].startswith("system health-check") for call in device.calls)
    assert result["verdict"] == "incomplete"


def test_unenrolled_health_checks_are_not_read():
    result = run(Device(), auth=Auth(adc_health_checks=()))
    assert result["missing"] == [{"step": "health_check_config:HC_HTTP_APP", "reason": "unsupported",
                                  "detail": "health check is not enrolled in adc_health_checks"}]


@pytest.mark.parametrize("status,message", [
    ("Version: FortiADC-KVM v7.6.6,build0676,260522 (GA.M)\n", "config_platform_not_supported"),
    ("Version: FortiGate-VM64-KVM v7.6.7,build3704,release\n", "config_platform_not_supported"),
    (TimeoutError("timed out"), "identity-unverifiable"),
])
def test_other_identity_refuses_and_reads_nothing_else(status, message):
    device = Device(status=status)
    with pytest.raises(ValueError, match=message):
        run(device)
    assert device.calls == [("identity", "get system status")]


@pytest.mark.parametrize("auth,virtual_server,vdom", [
    (Auth(), "VS_OTHER", "root"), (Auth(), VS, "other"), (Auth(config_access=()), VS, "root"),
    (SimpleNamespace(**{**vars(Auth), **vars(Auth()), "ssh_platform": "fortios"}), VS, "root"),
])
def test_out_of_scope_requests_touch_no_device(auth, virtual_server, vdom):
    device = Device()
    with pytest.raises(ValueError):
        run(device, auth, virtual_server, vdom)
    assert device.calls == []


def test_verdict_needs_every_required_step():
    executed = {"vs_config", "pool_config", "slb_vs_stat", "system_performance"}
    assert rules.verdict([], [], executed) == "no_fault_in_checked_data"
    for step in sorted(executed):
        assert rules.verdict([], [], executed - {step}) == "incomplete"
    assert rules.verdict([{"id": "F-DOS"}, {"id": "F-WAF"}, {"id": "F-NO-HC"}], [], executed) == "no_fault_in_checked_data"


def test_any_missing_step_makes_the_verdict_incomplete_even_with_all_required_steps():
    executed = {"vs_config", "pool_config", "slb_vs_stat", "system_performance"}
    missing = [{"step": "tls_handshake_stats", "reason": "permission_denied"}]
    assert rules.verdict([], missing, executed) == "incomplete"
    assert rules.verdict([{"id": "F-MEMBER-DOWN"}], missing, executed) == "incomplete"


ALIAS = "adc"
ENTRY = SimpleNamespace(credential="fixture-account", name=ALIAS, address="192.0.2.30", port=22,
                        host_key_fingerprint="SHA256:" + "A" * 43, legacy_ssh=None)


def _section(queries=("system_status", "slb_vs_stat", "slb_load", "system_performance"), **changes):
    helper = {"account_role": "read-only", "ssh_platform": "fortiadc", "enabled_queries": list(queries),
              "read_inventory": {"config_access": ["read"], "adc_virtual_servers": [VS], "adc_vdoms": ["root"]},
              "egress": {"addresses": ["192.0.2.30"], "tcp_ports": [22], "udp_ports": [], "tcp_port_ranges": [],
                         "udp_port_ranges": [], "allow_icmp": False, "allow_dns": False, "tls_server_names": []}}
    helper.update(changes)
    return inventory.section(SimpleNamespace(**{**vars(ENTRY), "helper": helper}))


def test_proxy_accepts_only_enrolled_names_and_a_complete_query_plan():
    args = proxy.Proxy._validate_tool_arguments("triage_slb", {"target": ALIAS, "virtual_server": VS})
    proxy.Proxy._authorize_tool("triage_slb", args, ENTRY, _section())
    for bad in ({"virtual_server": "VS X"}, {"virtual_server": VS, "vdom": "a" * 40}, {"virtual_server": 1},
                {"virtual_server": VS, "extra": 1}, {}):
        with pytest.raises(proxy.ToolArgumentsError):
            proxy.Proxy._validate_tool_arguments("triage_slb", {"target": ALIAS, **bad})
    for section, call in (
            (_section(), {"target": ALIAS, "virtual_server": "VS_OTHER"}),
            (_section(), {"target": ALIAS, "virtual_server": VS, "vdom": "other"}),
            (_section(queries=("system_status", "slb_vs_stat", "slb_load")), {"target": ALIAS, "virtual_server": VS}),
            (_section(read_inventory={"adc_virtual_servers": [VS], "adc_vdoms": ["root"]}),
             {"target": ALIAS, "virtual_server": VS})):
        with pytest.raises(proxy.PolicyScopeError):
            proxy.Proxy._authorize_tool("triage_slb", call, ENTRY, section)


def test_rate_plan_is_reserved_whole_before_anything_runs(monkeypatch):
    gateway = proxy.Proxy()
    monkeypatch.setattr(proxy.time, "monotonic", lambda: 100.0)
    limit = {"requests": 30, "window_seconds": 60}
    gateway.rate_history[ALIAS] = deque([50.0 + index for index in range(14)])
    with pytest.raises(proxy.RateLimitError) as refused:
        gateway._consume_rate_limit(ALIAS, limit, rules.RATE_COST)
    assert len(gateway.rate_history[ALIAS]) == 14
    assert refused.value.data["retry_after_seconds"] == 10
    gateway.rate_history[ALIAS].popleft()
    gateway._consume_rate_limit(ALIAS, limit, rules.RATE_COST)
    assert len(gateway.rate_history[ALIAS]) == 30
    assert proxy.TRIAGE_SLB_RATE_COST == rules.RATE_COST


def test_target_scope_shows_the_plan_until_its_window_passes(monkeypatch):
    gateway = proxy.Proxy()
    limit = {"requests": 30, "window_seconds": 60}
    clock = [100.0]
    monkeypatch.setattr(proxy.time, "monotonic", lambda: clock[0])
    gateway._consume_rate_limit(ALIAS, limit, proxy.TRIAGE_READS["triage_slb"])
    assert gateway._rate_status(ALIAS, limit)["used"] == 17
    clock[0] = 159.0
    assert gateway._rate_status(ALIAS, limit)["used"] == 17
    clock[0] = 161.0
    assert gateway._rate_status(ALIAS, limit)["used"] == 0


def test_proxy_charges_the_whole_plan_and_keeps_the_capture_deadline():
    section = _section()
    relay = proxy.Proxy()
    credential = SimpleNamespace(login="reader", kind="password", use=lambda: "auth-canary-17")
    with mock.patch.object(relay, "_target", return_value=(ENTRY, section, None)), \
            mock.patch.object(relay, "_credential", return_value=credential), \
            mock.patch.object(relay, "_consume_rate_limit") as charged, \
            mock.patch.object(proxy.time, "monotonic", return_value=100):
        forwarded = relay.request(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "triage_slb", "arguments": {"target": ALIAS, "virtual_server": VS}}}).encode())
    assert forwarded is not None
    assert charged.call_args.args == (ALIAS, section.rate_limit, 17)
    assert relay.pending_deadlines[1] - 100 == 670
