"""NXOS-HEALTH through the MCP server and its production proxy, using captured CLI replies."""

import asyncio
import json
import re
from pathlib import Path

import pytest

from netops import worker
from netops_helper import engine, proxy, server
from test_proxy_contracts import _device, _egress, _inventory, _write


PROFILE = "cisco_nxos"
FIXTURES = Path(__file__).parent / "fixtures/real/cisco_nxos"
LAB = FIXTURES / "nxos_health_9.3.12"
HEALTH = ("version", "system_resources", "environment", "modules", "processes_cpu", "ntp_status", "ntp_associations")
COMMANDS = {
    "version": "show version", "system_resources": "show system resources", "environment": "show environment",
    "modules": "show module", "processes_cpu": "show processes cpu", "ntp_status": "show ntp status",
    "ntp_associations": "show ntp peer-status", "log": "show logging last 40", "logging_info": "show logging info",
    "hsrp_detail": "show hsrp detail", "vrrp_detail": "show vrrp detail", "vrrpv3_detail": "show vrrpv3 detail",
    "object_tracking": "show track",
}


def lab(query):
    return (LAB / f"{query}.txt").read_text()


@pytest.fixture
def public(tmp_path, monkeypatch):
    replies = {command: (16 if query in {"hsrp_detail", "vrrp_detail", "vrrpv3_detail"} else 0, lab(query))
               for query, command in COMMANDS.items()}
    calls = []
    private = tmp_path / "helper"
    private.mkdir()
    _write(private / "vault.json", {"version": 2, "credentials": {
        "device-a-account": {"kind": "password", "login": "reader", "value": "fixture-password"},
    }}, 0o600)
    path = tmp_path / "inventory.json"
    monkeypatch.setattr(worker, "STATE", tmp_path)
    monkeypatch.setattr(proxy, "INVENTORY", path)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    def transport(auth, profile, command, **kwargs):
        assert profile == PROFILE
        calls.append(command)
        return replies[command]

    monkeypatch.setattr(engine, "_exec_read", transport)
    bridge = worker.HelperBridge()

    def ask(tool="ssh_read", *, enabled=None, **args):
        section = {
            "account_role": "read-only", "ssh_platform": PROFILE, "device_types": ["switch"],
            "enabled_queries": enabled if enabled is not None else [*HEALTH, "log_history", "logging_info",
                                                                   "hsrp_detail", "vrrp_detail", "vrrpv3_detail",
                                                                   "object_tracking"],
            "read_inventory": {"interfaces": ["Ethernet1/3"]},
            "egress": {**_egress(), "tcp_ports": [22]},
            "rate_limit": {"requests": 60, "window_seconds": 60},
        }
        _write(path, _inventory(_device(section, PROFILE)))
        if tool == "ssh_read":
            args.update(platform=PROFILE)
        result = asyncio.run(bridge.call(server.mcp, tool, {"target": "device-a", **args}))
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])

    return ask, replies, calls


def test_public_health_and_empty_ntp(public):
    ask, _, calls = public
    result = ask("triage_health")
    assert result["ok"] and result["identity"]["uptime"] in lab("version")
    assert result["system_resources"]["load_average"]["five_minutes"] == 0.37
    assert result["system_resources"]["memory_kib"]["used"] == 3989048
    assert result["processes_cpu"]["one_minute_percent"] == 17
    assert [module["slot"] for module in result["modules"]] == [1, 27]
    assert result["environment"]["unavailable"] == ["power", "fan", "temperature"]
    assert result["verdict"] == "incomplete"
    assert result["ntp"]["synchronized"] is False and result["ntp"]["peers"] == []
    assert result["ntp"]["offset_status"] == "not_reported"
    assert calls == [COMMANDS[query] for query in HEALTH]


def test_health_refusal_truncated_and_unknown_firmware(public):
    ask, replies, calls = public
    replies["show version"] = 0, lab("version").replace("9.3(12)", "9.3(13)")
    replies["show processes cpu"] = 0, lab("processes_cpu") + "--More--"
    replies["show ntp peer-status"] = 0, "% Authorization failed\n"
    result = ask("triage_health", enabled=[query for query in HEALTH if query != "environment"])
    missing = {item["step"]: item["reason"] for item in result["missing"]}
    assert missing == {"processes_cpu": "truncated", "ntp_associations": "permission_denied",
                       "environment": "permission_denied"}
    assert "show environment" not in calls and result["system_resources"]["memory_kib"]["total"]
    assert result["ntp"]["synchronized"] is None
    assert result["firmware_support"]["status"] == "untested"


def test_local_log_filter_cap_and_destination_status(public):
    ask, _, _ = public
    window = {"begin_date": "2026-11-20", "begin_time": "06:58:00", "end_date": "2026-11-20", "end_time": "06:59:32"}
    result = ask(query="log_history", parameters={"count": "40", "severity": "errors", **window})
    assert result["complete"] and result["log_history"]["scanned_events"] == 40
    assert result["log_history"]["matched_events"] > 0
    assert "%VSHD-5-" not in result["untrusted_device_output"]
    assert "06:59:32" not in result["untrusted_device_output"]
    result = ask(query="log_history", parameters={"count": "40"})
    assert not result["complete"] and result["status"] == "incomplete"
    assert result["log_history"]["source"] == "local_logfile"
    result = ask(query="logging_info")
    assert result["logging"] == {"complete": True, "destinations": [], "enabled": False, "status": "ok"}


def test_port_filter_uses_exact_interface_and_flags_pager(public):
    ask, replies, _ = public
    raw = (FIXTURES / "nexus9300v_9.3.12/log_messages.txt").read_text()
    replies["show logging last 40"] = (0, raw + "\n--More--")
    result = ask(query="log_history", parameters={"count": "40", "interface": "Ethernet1/3"})
    assert result["ok"] and not result["complete"]
    lines = result["untrusted_device_output"].splitlines()
    assert lines and all(re.search(r"\bEthernet1/3(?![\w/.])", line) for line in lines)
    assert "--More--" not in result["untrusted_device_output"]


@pytest.mark.parametrize("parameters", [
    {"count": "1001"}, {"count": "40; show version"}, {"count": "40", "begin_date": "2026-11-20"},
    {"count": "40", "interface": "Ethernet1/30"},
])
def test_log_scope_refused_before_cli(public, parameters):
    ask, _, calls = public
    assert not ask(query="log_history", parameters=parameters).get("ok")
    assert not calls


@pytest.mark.parametrize("query", ["hsrp_detail", "vrrp_detail", "vrrpv3_detail"])
def test_measured_gateway_refusal(public, query):
    ask, _, calls = public
    result = ask(query=query)
    assert result["ok"] is False and result["complete"] is False and result["rc"] == 16
    assert calls[-1] == COMMANDS[query]


def test_empty_tracking_is_success(public):
    ask, _, _ = public
    result = ask(query="object_tracking")
    assert result["ok"] and result["gateway"]["status"] == "empty"
    assert result["gateway"]["records"] == []


DOCS = FIXTURES.parents[1] / "docs/cisco_nxos/nxos-health"


def test_documented_physical_sensors_and_selected_ntp_peer(public):
    ask, replies, _ = public
    for query in ("environment", "ntp_associations"):
        replies[COMMANDS[query]] = 0, (DOCS / f"{query}.txt").read_text()
    result = ask("triage_health")
    assert result["complete"], result["missing"]
    assert result["environment"]["fan"][0]["state"] == "Ok"
    assert result["environment"]["power"][0]["output_watts"] == 805
    assert result["environment"]["temperature"][0]["current_celsius"] == 32
    assert result["ntp"]["synchronized"] is True
    selected, = (peer for peer in result["ntp"]["peers"] if peer["selected"])
    assert selected["reach_octal"] == "377" and selected["delay_ms"] == 0.00107
    assert result["ntp"]["offset_ms"] is None

    # A CLI snapshot with a declared count that no longer agrees with the returned rows.
    rc, peers = replies[COMMANDS["ntp_associations"]]
    replies[COMMANDS["ntp_associations"]] = rc, peers.rsplit("\n", 2)[0] + "\n"
    result = ask("triage_health")
    assert not result["complete"] and result["ntp"]["synchronized"] is None
    assert {"step": "ntp_associations", "reason": "unparsed"} in result["missing"]


@pytest.mark.parametrize("query,field,expected", [
    ("hsrp_detail", "hello_time", "1 sec"),
    ("vrrp_detail", "advertisement_interval", "200"),
    ("vrrpv3_detail", "advertisement_interval", "2000 msec"),
    ("object_tracking", "tracked_by", ["VRRPV3 Vlan20 1"]),
])
def test_documented_populated_gateway(public, query, field, expected):
    ask, replies, _ = public
    reply = (DOCS / f"{query}.txt").read_text()
    replies[COMMANDS[query]] = 0, reply
    result = ask(query=query)
    assert result["complete"], result["gateway"]
    assert result["gateway"]["records"][0][field] == expected

    replies[COMMANDS[query]] = 0, reply + "Unexpected CLI row\n--More--"
    result = ask(query=query)
    assert result["ok"] and result["status"] == "incomplete" and not result["complete"]


def test_log_audit_credentials_and_unknown_continuation_are_withheld(public):
    ask, replies, _ = public
    events = lab("log")
    logs = events.replace("<REDACTED>", "logged command: username demo password xy")
    replies["show logging last 40"] = 0, logs + "continuation with invented-secret-tail\n--More--"
    result = ask(query="log_history", parameters={"count": "40"})
    output = result["untrusted_device_output"]
    assert result["log_history"]["status"] == "incomplete"
    assert "password xy" not in output and "invented-secret-tail" not in output
    assert "%KERN-3-SYSTEM_MSG:" in output


def test_log_continuation_keeps_the_filtered_snapshot_and_incomplete_coverage(public):
    ask, _, calls = public
    result = ask(query="log_history", parameters={"count": "40"}, max_bytes=1024)
    first = result
    output = first["untrusted_device_output"]
    while result["next_offset"] is not None:
        result = ask(query="log_history", parameters={"count": "40"}, offset=result["next_offset"],
                     max_bytes=1024, content_sha256=first["content_sha256"])
        assert result["ok"] and result["log_history"] == first["log_history"] and not result["complete"]
        output += result["untrusted_device_output"]
    assert output.splitlines()[-1].startswith("2026 Nov 20")
    assert len(output.splitlines()) == 40 and calls.count("show logging last 40") == 1


def test_gateway_authentication_label_and_same_line_pager(public):
    ask, replies, _ = public
    reply = (DOCS / "hsrp_detail.txt").read_text() + "  Authentication text zz\x1b[7m--More--\x1b[0m"
    replies[COMMANDS["hsrp_detail"]] = 0, reply
    result = ask(query="hsrp_detail")
    assert not result["complete"] and result["status"] == "incomplete"
    assert "text zz" not in result["untrusted_device_output"]


def test_documented_enabled_syslog_destination_and_incomplete_row(public):
    ask, replies, _ = public
    capture = (DOCS / "logging_info.txt").read_text()
    replies[COMMANDS["logging_info"]] = 0, capture
    summary = ask(query="logging_info")["logging"]
    assert summary["enabled"] and summary["complete"]
    assert summary["destinations"][0]["transport"] == "secure"
    assert summary["destinations"][0]["port"] == "6514"
    replies[COMMANDS["logging_info"]] = 0, capture.split("server port:", 1)[0]
    summary = ask(query="logging_info")["logging"]
    assert summary["enabled"] and not summary["complete"]


@pytest.mark.parametrize("template", [
    "snmp-server user observer readers auth sha {auth} priv aes-128 {priv}",
    "auth: {auth} priv: {priv}",
    "key={auth} secret={priv}",
])
def test_nxos_log_credentials_from_arbitrary_facility_are_absent_from_the_snapshot(public, template):
    ask, replies, _ = public
    original = lab("log")
    snapshots = []
    for auth_value, priv_value in (("authZ9", "privZ9"), ("ax", "px")):
        replies["show logging last 40"] = 0, (
            "2026 Nov 20 06:57:00 %OTHER-5-NOTICE: "
            + template.format(auth=auth_value, priv=priv_value) + "\n" + original
        )
        first = ask(query="log_history", parameters={"count": "40"}, max_bytes=1024)
        assert first["next_offset"] is not None
        snapshots.append((first["content_sha256"], first["untrusted_device_output"]))
    assert snapshots[0] == snapshots[1]
    assert "%OTHER-5-NOTICE:" in snapshots[0][1]
    assert all(value not in snapshots[0][1] for value in ("authZ9", "privZ9"))


@pytest.mark.parametrize("query", ["hsrp_detail", "vrrp_detail", "vrrpv3_detail"])
def test_nxos_gateway_authentication_continuation_is_absent_from_the_snapshot(public, query):
    ask, replies, calls = public
    denied = ask(query=query)
    assert not denied["ok"] and calls[-1] == COMMANDS[query]
    example = (DOCS / f"{query}.txt").read_text()
    snapshots = []
    for value in ("fhrpZ9", "xz"):
        replies[COMMANDS[query]] = 0, example + (
            "  Authentication MD5\n"
            f"    Unrecognized detail: {value}\n"
            "  Virtual MAC address is 0000.5e00.0101\n"
        )
        reply = ask(query=query)
        assert reply["ok"] and not reply["complete"]
        snapshots.append((reply["content_sha256"], reply["untrusted_device_output"]))
    assert snapshots[0] == snapshots[1]
    assert "fhrpZ9" not in snapshots[0][1]
    assert "Virtual MAC address" in snapshots[0][1]


def test_nxos_module_online_failure_is_reported_even_if_module_is_operational(public):
    ask, replies, _ = public
    for query in ("environment", "ntp_associations"):
        replies[COMMANDS[query]] = 0, (DOCS / f"{query}.txt").read_text()
    _, peers = replies[COMMANDS["ntp_associations"]]
    peers = "\n".join(line for line in peers.splitlines() if not line.startswith("=127.127.1.0"))
    replies[COMMANDS["ntp_associations"]] = 0, peers.replace("Total peers : 2", "Total peers : 1")
    original = lab("modules")
    passing = ask("triage_health")
    assert passing["complete"] and passing["verdict"] == "no_fault_in_checked_data"
    replies["show module"] = 0, original.replace("1    Pass", "1    Fail")
    failed = ask("triage_health")
    assert failed["complete"] and failed["verdict"] == "fault_found"
    assert {"rule": "module_status", "query": "modules"} in failed["findings"]
    assert failed["modules"][0]["state"] == "ok"
    assert failed["modules"][0]["online_diagnostic_status"] == "Fail"
