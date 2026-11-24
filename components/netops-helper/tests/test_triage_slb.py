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
                               "adc_health_checks": ("HC_HTTP_APP",), "addresses": ("192.0.2.11", "192.0.2.12"),
                               "diagnostic_recipes": ("ping", "health_check_verify"), **inventory_changes}

    def require_tcp_port(self, port):
        assert port == 22


class Device:
    def __init__(self, configs=None, queries=None, status=STATUS):
        self.configs = {"load-balance virtual-server " + VS: vs_config(), "load-balance pool " + POOL: pool_config(),
                        "system health-check HC_HTTP_APP": HC,
                        **{"load-balance real-server RS_%d" % i:
                           "config load-balance real-server\n edit RS_%d\n set ip 192.0.2.%d\n next\nend\n" % (i, 10 + i)
                           for i in (1, 2)}, **(configs or {})}
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
        # This rule-test adapter models an attempted device read, including timeouts.
        attempt = engine._TRIAGE_READ_ATTEMPT.get()
        if attempt is not None:
            attempt[0] = True
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
    for step in result["next_steps"]:
        assert step["arguments"]["address"] == "192.0.2.12"
        proxy.Proxy._validate_tool_arguments(step["tool"], step["arguments"])

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


def test_member_states_are_joined_by_pool_and_id():
    # DERIVED: the measured vs_stat with DOWN states printing another pool that also has ids 1/2 (verification).
    other = vs_stat(("DOWN", "DOWN")).replace("real-server-pool: POOL_APP", "real-server-pool: POOL_OLD")
    result = run(Device(queries={"slb_vs_stat": other}))
    assert [member["runtime"] for member in result["chain"]["members"]] == [None, None]
    assert ids(result) == ["F-MISMATCH"]
    assert result["findings"][0]["fact"] == "config member ids [1, 2], vs_stat member ids [], vs_stat pools ['POOL_OLD']"
    assert result["next_steps"] == []


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
        ("vs_config", "local_refusal"), ("pool_config", "not_applicable")]
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


@pytest.mark.parametrize("status,code,reason", [
    ("Version: FortiGate-VM64-KVM v7.6.7,build3704,release\n", "config_platform_not_supported", "unsupported"),
    ("not an identity\n", "product_identity", "unparsed"),
    ("Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"
     "Command fail. Return code is -284 (CLI parsing error.)\nHostname: lab\n", "device_cli_error", "device_cli_error"),
    ("Command fail. Return code is -37 (permission denied)\n", "device_cli_error", "device_cli_error"),
    # live 1.0.7: an unreachable SSH target ended as -32603 "Role operation failed" instead of a structured result
    (TimeoutError("timed out synthetic-secret"), "timeout", "timeout"),
    (OSError("SSH closed synthetic-secret"), "ssh_unavailable", "ssh_unavailable"),
    (ConnectionRefusedError("synthetic-secret"), "connection_refused", "transport_error"),
])
def test_other_identity_or_transport_failure_is_structured_and_reads_nothing_else(status, code, reason):
    device = Device(status=status)
    result = run(device)
    assert device.calls == [("identity", "get system status")]
    assert (result["ok"], result["error_code"], result["failed_step"], result["verdict"]) == (
        False, code, "system_status", "incomplete")
    advice = engine._TRANSPORT_ADVICE.get(code)
    assert result["missing"] == [{"step": "system_status", "reason": reason, "error_code": code,
                                  **({"error": advice} if advice else {})}]
    if advice:
        assert result["error"] == advice
    assert (result["target"], result["virtual_server"], result["vdom"]) == (Auth().alias, VS, "root")
    assert result["vantage"]["kind"] == "device_cli_read" and result["vantage"]["packets_sent"] is False
    assert result["findings"] == [] and result["checked"] == []
    assert "synthetic-secret" not in str(result)


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
    gateway.triage_history[ALIAS] = deque([50.0 + index for index in range(30 - rules.RATE_COST + 1)])
    gateway.rate_history[ALIAS] = deque(gateway.triage_history[ALIAS])
    with pytest.raises(proxy.RateLimitError) as refused:
        gateway._consume_rate_limit(ALIAS, limit, rules.RATE_COST, triage=True)
    assert len(gateway.triage_history[ALIAS]) == 30 - rules.RATE_COST + 1
    assert refused.value.data["retry_after_seconds"] == 10
    gateway.triage_history[ALIAS].popleft()
    gateway.rate_history[ALIAS].popleft()
    gateway._consume_rate_limit(ALIAS, limit, rules.RATE_COST, triage=True)
    assert len(gateway.triage_history[ALIAS]) == 30 and len(gateway.rate_history[ALIAS]) == 30
    assert proxy.TRIAGE_SLB_RATE_COST == rules.RATE_COST


def test_target_scope_shows_the_plan_until_its_window_passes(monkeypatch):
    gateway = proxy.Proxy()
    limit = {"requests": 30, "window_seconds": 60}
    clock = [100.0]
    monkeypatch.setattr(proxy.time, "monotonic", lambda: clock[0])
    gateway._consume_rate_limit(ALIAS, limit, proxy.TRIAGE_READS["triage_slb"], triage=True)
    assert gateway._rate_status(ALIAS, limit, triage=True)["used"] == rules.RATE_COST
    assert gateway._rate_status(ALIAS, limit)["used"] == rules.RATE_COST
    clock[0] = 159.0
    assert gateway._rate_status(ALIAS, limit, triage=True)["used"] == rules.RATE_COST
    clock[0] = 161.0
    assert gateway._rate_status(ALIAS, limit, triage=True)["used"] == 0


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
    assert charged.call_args.args == (ALIAS, section.rate_limit, rules.RATE_COST)
    assert relay.pending_deadlines[1] - 100 == 670


def test_result_states_its_vantage():
    # live 1.0.7: tcp_probe said helper_host, a triage did not say where its facts come from
    result = run(Device())
    assert result["ok"] is True
    assert result["vantage"] == {
        "kind": "device_cli_read", "device": Auth().alias, "packets_sent": False,
        "sees": "the configuration and runtime state the FortiADC reports for the virtual server, its pool, members, "
                "health checks and profiles",
        "does_not_see": "whether new client connections pass through the virtual server; test that from a client"}


def test_down_followups_exclude_unenrolled_and_unread_addresses():
    for device, auth in (
        (Device(queries={"slb_vs_stat": vs_stat(("UP", "DOWN"))}), Auth(addresses=())),
        (Device(configs={"load-balance real-server RS_2": TimeoutError()},
                queries={"slb_vs_stat": vs_stat(("UP", "DOWN"))}), Auth()),
    ):
        result = run(device, auth)
        assert "F-MEMBER-DOWN" in ids(result)
        assert result["next_steps"] == []


def test_down_server_reads_are_bounded_and_repeated_servers_share_a_read(monkeypatch):
    monkeypatch.setattr(rules, "MAX_REAL_SERVERS", 1)
    result = run(Device(queries={"slb_vs_stat": vs_stat(("DOWN", "DOWN"))}))
    assert result["verdict"] == "incomplete"
    assert {"step": "real_server_config:RS_2", "reason": "truncated"} in result["missing"]
    assert {step["arguments"]["address"] for step in result["next_steps"]} == {"192.0.2.11"}
    device = Device(configs={"load-balance pool " + POOL: pool_config().replace("RS_2", "RS_1")},
                    queries={"slb_vs_stat": vs_stat(("DOWN", "DOWN"))})
    result = run(device)
    assert result["verdict"] == "fault_found"
    assert len([call for call in device.calls if call[:2] == ("config_read", "load-balance real-server RS_1")]) == 1
    assert {step["arguments"]["address"] for step in result["next_steps"]} == {"192.0.2.11"}


# --- Pool selection by schedule (1.0.9 item 12) -------------------------------------------------------------
# REAL captures of FortiADC-KVM 7.6.7 build 0676 in fixtures/real/fortiadc/fortiadc-kvm_7.6.7_schedule_20261114
# (see its PROVENANCE.md). They go through the real config_read and ssh_read paths; only the SSH transport
# (_exec_read for the configuration stream, _prompt_read for the PTY catalogue queries) is replaced.
# DERIVED texts are built from those captures by the functions below and named as such; STATUS and PERF stay
# the synthetic texts of this module (identity and resources are not under test here).

from pathlib import Path

SCHEDULE_DIR = Path(__file__).parent / "fixtures/real/fortiadc/fortiadc-kvm_7.6.7_schedule_20261114"
SVS = "netops-173-vs"
ADC_PROMPT = "FortiADC-KVM # "
VS_STAT_COMMAND = "diagnose server-load-balance vs_stat vdom root vs " + SVS
SLB_LOAD_COMMAND = "diagnose server-load-balance slb_load"


def real(name):
    with open(SCHEDULE_DIR / name, encoding="utf-8", newline="") as handle:
        return handle.read()


def exec_body(name):
    """DERIVED: the PTY body of an exec-channel capture, i.e. without the exec channel's prompt lines."""
    return "\n".join(line for line in real(name).split("\n") if line != ADC_PROMPT)


def object_view(table_capture, single_capture, name):
    """DERIVED: the object view of `name`, cut from the real whole-table capture into the frame of a real
    object-view capture (test_object_views_derive_exactly_from_the_table pins the method)."""
    lines = table_capture.split("\n")
    start = lines.index('  edit "%s"' % name)
    block = lines[start:lines.index("  next", start) + 1]
    frame = single_capture.split("\n")
    first = next(i for i, line in enumerate(frame) if line.startswith("  edit "))
    return "\n".join(frame[:first] + block + frame[frame.index("  next", first) + 1:])


def schedule_views():
    return {
        "load-balance virtual-server " + SVS: real("vs_schedule_full.txt"),
        "load-balance schedule-pool netops-173-sp-a": real("schedule_pool_sp_a_full.txt"),
        "load-balance schedule-pool netops-173-sp-b": object_view(
            real("schedule_pool_full.txt"), real("schedule_pool_sp_a_full.txt"), "netops-173-sp-b"),
        "system schedule-group netops-173-sg-now": real("schedule_group_sg_now_full.txt"),
        "system schedule-group netops-173-sg-off": object_view(
            real("schedule_group_full.txt"), real("schedule_group_sg_now_full.txt"), "netops-173-sg-off"),
    }


def schedule_auth():
    from dataclasses import replace
    from conftest import _target
    from netops_helper.auth import EgressPolicy
    from netops_helper.query_catalog import READ_QUERIES
    return replace(_target("fortiadc", "system_status"), enabled_queries=tuple(READ_QUERIES["fortiadc"]),
                   egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(2222,), allow_icmp=True),
                   read_inventory={**Auth().read_inventory, "adc_virtual_servers": (SVS,)})


@pytest.fixture
def schedule_wire(monkeypatch):
    """Answers device commands from the captures; `views`/`runtime` entries can be replaced per test."""
    from netops_helper import configuration
    configuration._SNAPSHOTS.clear()
    state = SimpleNamespace(calls=[], views=schedule_views(), runtime={
        VS_STAT_COMMAND: exec_body("vs_stat_schedule_exec.txt"),
        SLB_LOAD_COMMAND: exec_body("slb_load_schedule_exec.txt"),
        "get system performance": PERF})

    def exec_read(auth, platform, command, stdout_consumer=None):
        state.calls.append(command)
        if command == "get system status":
            body = STATUS
        elif command in state.runtime:
            body = state.runtime[command]
        else:
            assert command.startswith("show full-configuration "), command
            body = state.views[command[len("show full-configuration "):]]
        if stdout_consumer:
            encoded = body.encode()
            for index in range(0, len(encoded), 7):
                stdout_consumer(encoded[index:index + 7])
            return 0, ""
        return 0, body

    def prompt_read(auth, platform, command):
        state.calls.append(command)
        return None, state.runtime[command]

    monkeypatch.setattr(engine, "_exec_read", exec_read)
    monkeypatch.setattr(engine, "_prompt_read", prompt_read)
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    yield state
    configuration._SNAPSHOTS.clear()


def test_object_views_derive_exactly_from_the_table():
    assert object_view(real("schedule_pool_full.txt"), real("schedule_pool_sp_a_full.txt"),
                       "netops-173-sp-a") == real("schedule_pool_sp_a_full.txt")
    assert object_view(real("schedule_group_full.txt"), real("schedule_group_sg_now_full.txt"),
                       "netops-173-sg-now") == real("schedule_group_sg_now_full.txt")


def test_exec_capture_minus_prompt_lines_is_the_pty_body():
    pty = real("vs_stat_schedule_pty.txt").encode()
    assert engine._pty_body(pty, VS_STAT_COMMAND, ADC_PROMPT.encode()) == exec_body("vs_stat_schedule_exec.txt")


def test_hidden_stored_pool_leaves_the_virtual_server_configuration_unchanged():
    # Measured: a load-balance-pool stored before schedule-list enable is not printed by show full-configuration.
    assert real("vs_schedule_full.txt") == real("vs_schedule_stored_pool_full.txt")
    assert "load-balance-pool" not in real("vs_schedule_full.txt")
    assert "set schedule-pool-list netops-173-sp-a netops-173-sp-b \n" in real("vs_schedule_full.txt")


@pytest.mark.parametrize("section,name", [
    ("load-balance schedule-pool netops-173-sp-a", "schedule_pool_sp_a_full.txt"),
    ("system schedule-group netops-173-sg-now", "schedule_group_sg_now_full.txt"),
])
def test_config_read_returns_the_new_object_views_with_the_same_redaction(schedule_wire, section, name):
    result = engine.config_read(schedule_auth(), "fortiadc", section, redaction="full", include_defaults=True)
    assert schedule_wire.calls == ["get system status", "show full-configuration " + section]
    assert result["ok"] is True and result["capture_complete"] is True and result["next_offset"] is None
    assert result["config_scope"] == "device-account-visible" and result["unverified_count"] == 0
    assert result["credential_redactions"] == 0
    output = result["untrusted_device_output"]
    if section.startswith("system"):
        assert output == ("config system schedule-group\nedit netops-173-sg-now\nconfig schedule-member\nedit 1\n"
                          "    set type weekly-recurring\n    set starttime-of-startdate 00:00\n"
                          "    set endtime-of-enddate 23:59\n    set day-of-week saturday\nnext\nend\nnext\nend\n")
    else:
        assert output == ("config load-balance schedule-pool\nedit netops-173-sp-a\n"
                          "    set load-balance-pool netops-173-pool-a\n    set schedule netops-173-sg-now\nnext\nend\n")


@pytest.mark.parametrize("section,body", [
    ("load-balance schedule-pool netops-173-sp-b", "schedule_pool_sp_a_full.txt"),
    ("load-balance schedule-pool netops-173-sp-a", "schedule_pool_full.txt"),
    ("system schedule-group netops-173-sg-now", "schedule_group_full.txt"),
])
def test_config_read_refuses_another_or_more_than_the_requested_object(schedule_wire, section, body):
    schedule_wire.views[section] = real(body)
    with pytest.raises(ValueError):
        engine.config_read(schedule_auth(), "fortiadc", section, redaction="full", include_defaults=True)


def test_schedule_parsers_read_the_redacted_real_views_literally(schedule_wire):
    auth = schedule_auth()

    def view(section):
        return engine.config_read(auth, "fortiadc", section, redaction="full", include_defaults=True)[
            "untrusted_device_output"]
    vs = rules.virtual_server_config(view("load-balance virtual-server " + SVS), SVS)
    assert (vs["schedule_list"], vs["schedule_pool_list"], vs["content_routing"], vs["pool"]) == (
        "enable", ["netops-173-sp-a", "netops-173-sp-b"], "disable", None)
    assert rules.schedule_pool_config(view("load-balance schedule-pool netops-173-sp-b"), "netops-173-sp-b") == {
        "schedule": "netops-173-sg-off", "pool": "netops-173-pool-b"}
    assert rules.schedule_group_config(view("system schedule-group netops-173-sg-off"), "netops-173-sg-off") == {
        "members": [{"id": 1, "fields": {"type": "weekly-recurring", "starttime-of-startdate": "00:00",
                                         "endtime-of-enddate": "23:59", "day-of-week": "wednesday"}}]}
    group = view("system schedule-group netops-173-sg-now")
    for changed in (group.replace("weekly-recurring", "yearly-recurring"),
                    group.replace("set day-of-week saturday", "set active-now yes"),
                    group.replace("config schedule-member", "config member")):
        with pytest.raises(rules.TriageParseError):
            rules.schedule_group_config(changed, "netops-173-sg-now")
    entry = view("load-balance schedule-pool netops-173-sp-a")
    with pytest.raises(rules.TriageParseError):
        rules.schedule_pool_config(entry.replace("    set schedule netops-173-sg-now\n", ""), "netops-173-sp-a")


def test_real_runtime_without_pool_and_with_the_stored_pool_is_read_literally():
    parsed = rules.parse_vs_stat(exec_body("vs_stat_schedule_exec.txt"), SVS, "root")
    assert parsed == {"availability": "HEALTHY", "pools": [], "no_rs": True, "counters": {
        "APP Response": 0, "Client RTT": 0, "Concurrent Connections": 0, "Inbound Throughput": 0,
        "Outbound Throughput": 0, "Requests": 0, "Server RTT": 0}}
    assert rules.parse_slb_load(exec_body("slb_load_schedule_exec.txt"), SVS) == {
        "present": True, "pools": [], "no_rs": True}
    assert rules.parse_slb_load(exec_body("slb_load_schedule_exec.txt"), "VS_APP_HTTP")["pools"][0]["name"] == POOL
    stored = rules.parse_vs_stat(exec_body("vs_stat_stored_pool_exec.txt"), SVS, "root")
    assert "no_rs" not in stored and [p["name"] for p in stored["pools"]] == ["netops-173-pool-b"]
    assert [(m["id"], m["hc_state"], m["last_state_change"]) for m in stored["pools"][0]["members"]] == [(1, "UP", None)]
    assert rules.parse_vs_stat(exec_body("vs_stat_stored_pool_offwindow_exec.txt"), SVS, "root")["availability"] == "DEAD"
    assert rules.parse_slb_load(exec_body("slb_load_stored_pool_exec.txt"), SVS)["pools"] == [
        {"name": "netops-173-pool-b", "members": [{"id": 1, "status": 1, "weight": 0}]}]
    body = exec_body("vs_stat_schedule_exec.txt")
    for changed in (body + "\n\t\treal-server-pool: P", body.replace("no rs for this vs", "no rs for this vs\nno rs for this vs"),
                    body.replace("\tvirtual-server:", "no rs for this vs\n\tvirtual-server:")):
        with pytest.raises(rules.TriageParseError):
            rules.parse_vs_stat(changed, SVS, "root")
    load = exec_body("slb_load_schedule_exec.txt")
    with pytest.raises(rules.TriageParseError):
        rules.parse_slb_load(load + "\n\t\treal-server P", SVS)


def run_schedule(wire, reports=None):
    token = engine.progress.bind(lambda *report: reports.append(report)) if reports is not None else None
    try:
        return engine.triage_slb(schedule_auth(), SVS)
    finally:
        if token is not None:
            engine.progress.unbind(token)


def test_schedule_virtual_server_lists_candidates_and_claims_no_active_pool(schedule_wire):
    reports = []
    result = run_schedule(schedule_wire, reports)
    assert result["missing"] == [] and result["verdict"] == "no_fault_in_checked_data"
    assert result["checked"] == ["schedule_group:netops-173-sg-now", "schedule_group:netops-173-sg-off",
                                 "schedule_pool:netops-173-sp-a", "schedule_pool:netops-173-sp-b",
                                 "slb_load", "slb_vs_stat", "system_performance", "vs_config"]
    # Every config_read and ssh_read verifies the identity again before its own command.
    assert schedule_wire.calls[0] == "get system status"
    assert [call for call in schedule_wire.calls if call != "get system status"] == [
        "show full-configuration load-balance virtual-server " + SVS,
        "show full-configuration load-balance schedule-pool netops-173-sp-a",
        "show full-configuration load-balance schedule-pool netops-173-sp-b",
        "show full-configuration system schedule-group netops-173-sg-now",
        "show full-configuration system schedule-group netops-173-sg-off",
        VS_STAT_COMMAND, SLB_LOAD_COMMAND, "get system performance"]
    assert reports[-1][:2] == (9, rules.RATE_COST)
    chain, sources = result["chain"], {}
    vs_source = chain["schedule"][0]["sources"][0]
    assert vs_source["section"] == "load-balance virtual-server " + SVS
    assert [(item["entry"], item["schedule"], item["pool"], [s["section"] for s in item["sources"]])
            for item in chain["schedule"]] == [
        ("netops-173-sp-a", "netops-173-sg-now", "netops-173-pool-a",
         [vs_source["section"], "load-balance schedule-pool netops-173-sp-a"]),
        ("netops-173-sp-b", "netops-173-sg-off", "netops-173-pool-b",
         [vs_source["section"], "load-balance schedule-pool netops-173-sp-b"])]
    assert [(g["name"], g["members"], [s["section"] for s in g["sources"]]) for g in chain["schedule_groups"]] == [
        ("netops-173-sg-now", [{"id": 1, "fields": {"type": "weekly-recurring", "starttime-of-startdate": "00:00",
                                                     "endtime-of-enddate": "23:59", "day-of-week": "saturday"}}],
         ["system schedule-group netops-173-sg-now"]),
        ("netops-173-sg-off", [{"id": 1, "fields": {"type": "weekly-recurring", "starttime-of-startdate": "00:00",
                                                     "endtime-of-enddate": "23:59", "day-of-week": "wednesday"}}],
         ["system schedule-group netops-173-sg-off"])]
    pool = chain["pool"]
    assert (pool["name"], pool["config"], pool["selection"], pool["candidates_complete"]) == (None, None, "schedule", True)
    assert [(r["name"], r["relation"], r.get("entries"), [s["section"] for s in r["sources"]])
            for r in pool["references"]] == [
        ("netops-173-pool-a", "configured_candidate", ["netops-173-sp-a"],
         [vs_source["section"], "load-balance schedule-pool netops-173-sp-a"]),
        ("netops-173-pool-b", "configured_candidate", ["netops-173-sp-b"],
         [vs_source["section"], "load-balance schedule-pool netops-173-sp-b"])]
    assert chain["vs"]["runtime"]["no_rs"] is True and chain["vs"]["runtime"]["pools"] == []
    assert chain["load"] == {"present": True, "pools": [], "no_rs": True}
    assert chain["members"] == [] and chain["health_checks"] == [] and chain["real_servers"] == {}
    assert ids(result) == ["F-POOL-BY-SCHEDULE"]
    finding = result["findings"][0]
    assert finding["fact"] == ("schedule-list enable, schedule-pool-list netops-173-sp-a netops-173-sp-b, "
                               "candidate pools netops-173-pool-a netops-173-pool-b; the device output does not "
                               "name the pool the schedule selects")
    assert [s["section"] for s in finding["sources"]] == [
        vs_source["section"], "load-balance schedule-pool netops-173-sp-a", "load-balance schedule-pool netops-173-sp-b"]
    assert all(len(s["content_sha256"]) == 64 and s["call"] == "config_read" for s in finding["sources"])
    text = json.dumps(result).casefold()
    assert "not_applicable" not in text and "active pool" not in text and "reported_by_vs_stat" not in text
    print(json.dumps({key: result[key] for key in ("verdict", "missing", "findings")}
                     | {"pool": pool, "schedule": [{k: v for k, v in item.items() if k != "sources"}
                                                   for item in chain["schedule"]]}, indent=1))


def test_stored_pool_reported_by_vs_stat_is_qualified_not_a_mismatch(schedule_wire):
    schedule_wire.runtime[VS_STAT_COMMAND] = exec_body("vs_stat_stored_pool_exec.txt")
    schedule_wire.runtime[SLB_LOAD_COMMAND] = exec_body("slb_load_stored_pool_exec.txt")
    result = run_schedule(schedule_wire)
    assert ids(result) == ["F-POOL-BY-SCHEDULE"] and result["verdict"] == "no_fault_in_checked_data"
    reported = [r for r in result["chain"]["pool"]["references"] if r["relation"] == "reported_by_vs_stat"]
    assert [(r["name"], [s["query"] for s in r["sources"]]) for r in reported] == [("netops-173-pool-b", ["slb_vs_stat"])]
    assert result["chain"]["members"] == []


def test_no_schedule_window_is_a_literal_availability_fault_with_a_schedule_hypothesis(schedule_wire):
    schedule_wire.runtime[VS_STAT_COMMAND] = exec_body("vs_stat_stored_pool_offwindow_exec.txt")
    schedule_wire.runtime[SLB_LOAD_COMMAND] = exec_body("slb_load_stored_pool_exec.txt")
    result = run_schedule(schedule_wire)
    assert ids(result) == ["F-VS-AVAIL", "F-POOL-BY-SCHEDULE"] and result["verdict"] == "fault_found"
    assert result["findings"][0]["fact"] == "availability:DEAD"
    assert result["hypotheses"] == [{"text": "no schedule window may be active at the device time; compare the "
                                             "schedule group members with the device clock",
                                     "based_on": ["F-VS-AVAIL", "F-POOL-BY-SCHEDULE"]}]


def test_runtime_pool_outside_the_candidates_is_named_without_a_mismatch(schedule_wire):
    # DERIVED: the real stored-pool vs_stat with the pool renamed to one that no schedule-pool entry names.
    schedule_wire.runtime[VS_STAT_COMMAND] = exec_body("vs_stat_stored_pool_exec.txt").replace(
        "netops-173-pool-b", "netops-173-pool-c")
    result = run_schedule(schedule_wire)
    assert ids(result) == ["F-POOL-BY-SCHEDULE", "F-POOL-NOT-CANDIDATE"]
    assert result["verdict"] == "no_fault_in_checked_data"
    finding = result["findings"][1]
    assert finding["object"] == "netops-173-pool-c" and finding["layer"] == "runtime"
    assert [s.get("query") or s.get("section") for s in finding["sources"]][:2] == [
        "slb_vs_stat", "load-balance virtual-server " + SVS]


def test_unreadable_or_truncated_schedule_entries_keep_the_result_incomplete(schedule_wire, monkeypatch):
    schedule_wire.views["load-balance schedule-pool netops-173-sp-b"] = real("schedule_pool_full.txt")
    schedule_wire.runtime[VS_STAT_COMMAND] = exec_body("vs_stat_stored_pool_exec.txt").replace(
        "netops-173-pool-b", "netops-173-pool-c")
    result = run_schedule(schedule_wire)
    assert [(m["step"], m["reason"]) for m in result["missing"]] == [("schedule_pool:netops-173-sp-b", "device_cli_error")]
    assert result["chain"]["pool"]["candidates_complete"] is False
    assert result["chain"]["schedule"][1] == {"entry": "netops-173-sp-b", "schedule": None, "pool": None,
                                              "sources": [result["chain"]["schedule"][0]["sources"][0]]}
    assert ids(result) == ["F-POOL-BY-SCHEDULE"] and result["verdict"] == "incomplete"
    monkeypatch.setattr(rules, "MAX_SCHEDULE_ENTRIES", 1)
    schedule_wire.views = schedule_views()
    schedule_wire.calls.clear()
    result = run_schedule(schedule_wire)
    assert result["missing"] == [{"step": "schedule_pool:netops-173-sp-b", "reason": "truncated"}]
    assert [item["entry"] for item in result["chain"]["schedule"]] == ["netops-173-sp-a"]
    assert not any("sp-b" in call or "sg-off" in call for call in schedule_wire.calls)
    assert result["verdict"] == "incomplete"


def test_schedule_without_entries_and_content_routing_are_explicitly_missing(schedule_wire):
    vs = real("vs_schedule_full.txt")
    # DERIVED: the real virtual-server view without its schedule-pool-list line.
    schedule_wire.views["load-balance virtual-server " + SVS] = vs.replace(
        "    set schedule-pool-list netops-173-sp-a netops-173-sp-b \n", "")
    result = run_schedule(schedule_wire)
    assert result["missing"] == [{"step": "schedule_pool", "reason": "empty",
                                  "detail": "schedule-list enable without schedule-pool-list"}]
    assert result["chain"]["schedule"] == [] and result["verdict"] == "incomplete"
    # DERIVED: content-routing enabled in the real view without a content-routing-list (ADC-STATISTICS r2 ADC-C04: content
    # routing is followed through its entries, tests/test_adc_content_routing_adc.py; an empty list is reported as missing).
    schedule_wire.views["load-balance virtual-server " + SVS] = vs.replace(
        "set content-routing disable", "set content-routing enable")
    schedule_wire.calls.clear()
    result = run_schedule(schedule_wire)
    assert result["missing"] == [{"step": "content_routing", "reason": "empty",
                                  "detail": "content-routing enable without content-routing-list"}]
    assert result["chain"]["pool"]["selection"] == "content_routing" and "schedule" not in result["chain"]
    assert not any("schedule" in call for call in schedule_wire.calls)
    assert result["verdict"] == "incomplete"


def test_both_read_plans_fit_the_reserved_triage_budget():
    assert rules.STATIC_PLAN == rules.RATE_COST == engine.progress.TRIAGE_READS["triage_slb"]
    assert rules.SCHEDULE_PLAN == 12 + 2 * rules.MAX_SCHEDULE_ENTRIES <= rules.RATE_COST


def test_virtual_server_without_schedule_keeps_its_chain():
    result = run(Device())
    assert "selection" not in result["chain"]["pool"] and "schedule" not in result["chain"]
    assert result["chain"]["vs"]["config"]["schedule_list"] is None
    assert result["chain"]["vs"]["config"]["schedule_pool_list"] == []
    assert "no_rs" not in result["chain"]["vs"]["runtime"] and "no_rs" not in result["chain"]["load"]
