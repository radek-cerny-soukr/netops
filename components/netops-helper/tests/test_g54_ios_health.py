"""Classic IOS G54 reads through the public MCP bridge with captured CLI output."""

import asyncio
import json
from pathlib import Path

import pytest

from netops import worker
from netops_helper import engine, proxy, server
from test_g72_ios_xe_health import COMMANDS, DETAIL, docs, log_window
from test_proxy_contracts import _device, _egress, _inventory, _write


PROFILE = "cisco_ios"
FIXTURES = Path(__file__).parent / "fixtures"
REAL_IOS = FIXTURES / "real/cisco_ios"
HEALTH = ("version", "cpu", "memory", "environment", "ntp_status", "ntp_associations")
CLI = {**COMMANDS, "environment": "show env all", "log_history": "show logging"}


def lab(query, node="d-iosv", role="ro"):
    return (REAL_IOS / "g54" / f"{node}-{role}-{query}.out").read_text()


@pytest.fixture
def public(tmp_path, monkeypatch):
    answers = {CLI[query]: lab(query) for query in (*HEALTH, *DETAIL, "clock", "log_history")}
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

    def transport(auth, platform, command, **kwargs):
        assert platform == PROFILE
        calls.append(command)
        return 0, answers[command]

    monkeypatch.setattr(engine, "_exec_read", transport)
    bridge = worker.HelperBridge()

    def ask(query=None, parameters=None, *, admin=False, enabled=None, **options):
        section = {
            "account_role": "admin-bounded" if admin else "read-only", "ssh_platform": PROFILE,
            "device_types": ["router"], "enabled_queries": enabled if enabled is not None else (
                ["clock", "log_history"] if admin else [*HEALTH, *DETAIL, "clock", "log_history"]),
            "read_inventory": {"interfaces": ["GigabitEthernet0/1"]},
            "egress": {**_egress(), "tcp_ports": [22]},
            "rate_limit": {"requests": 60, "window_seconds": 60},
        }
        if admin:
            section["role_boundary"] = "catalogue"
        _write(path, _inventory(_device(section, PROFILE)))
        args = {"target": "device-a"}
        if query:
            args.update(platform=PROFILE, query=query, parameters=parameters or {}, **options)
        result = asyncio.run(bridge.call(server.mcp, "ssh_read" if query else "triage_health", args))
        if "structuredContent" in result:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])

    return answers, calls, ask


@pytest.mark.parametrize("node,version", [("d-iosv", "15.9(3)M12"), ("d-iosvl2", "15.2(20200924:215240)")])
def test_ios_health_and_ntp_across_nodes(public, node, version):
    answers, calls, ask = public
    for query in ("version", "cpu", "memory"):
        answers[CLI[query]] = lab(query, node)
    report = ask()
    assert report["ok"] and report["verdict"] == "incomplete"
    assert report["identity"]["os_version"] == version
    assert report["identity"]["uptime"] in lab("version", node)
    cpu = report["cpu"]
    assert cpu["five_seconds_minus_five_minutes_pp"] == cpu["five_seconds_percent"] - cpu["five_minutes_percent"]
    assert report["memory"]["Processor"]["total_bytes"] > 0
    assert report["ntp"] == {"enabled": False, "synchronized": False, "peers": [], "associations_complete": True}
    assert report["missing"] == [{"step": "environment", "reason": "permission_denied"}]
    assert calls == [CLI[query] for query in HEALTH]


def test_ios_hardware_and_synchronized_ntp(public):
    answers, _, ask = public
    answers[CLI["environment"]] = (FIXTURES / "docs/cisco_ios/g54/environment.out").read_text()
    for query in ("ntp_status", "ntp_associations"):
        answers[CLI[query]] = docs(query)
    report = ask()
    assert report["complete"], report.get("missing")
    assert report["environment"]["temperatures"] == [{"name": "System", "celsius": 41, "state": "GREEN"}]
    assert report["environment"]["power_supplies"] == [{"slot": "1", "state": "Good"}]
    assert report["environment"]["fans"] == [{"name": "FAN", "state": "OK"}]
    selected, = (peer for peer in report["ntp"]["peers"] if peer["selected"])
    assert selected["reach_octal"] == "377" and selected["successful_polls"] == 8
    assert selected["offset_ms"] == 11.18 and report["ntp"]["offset_ms"] == 0


@pytest.mark.parametrize("clock,synchronized,stratum,reference", [
    ("Clock is unsynchronized, stratum 16, no reference clock", False, 16, None),
    ("Clock is synchronized, stratum 6, reference is 192.0.2.7    ", True, 6, "192.0.2.7"),
])
def test_ios_ntp_clock_status(public, clock, synchronized, stratum, reference):
    answers, _, ask = public
    answers[CLI["ntp_status"]] = clock + "\nclock offset is 0.0000 msec, root delay is 0.00 msec\n"
    answers[CLI["ntp_associations"]] = docs("ntp_associations")
    report = ask()
    ntp = report["ntp"]
    assert ntp["synchronized"] is synchronized
    assert ntp["stratum"] == stratum and ntp["reference"] == reference
    assert ntp["complete"]
    assert {"step": "ntp_status", "reason": "unparsed"} not in report["missing"]


@pytest.mark.parametrize("reference,stratum", [(".INIT.", 16), ("127.127.1.1", 5)])
def test_ios_ntp_preserves_unreachable_peer_with_whole_dispersion(public, reference, stratum):
    answers, _, ask = public
    header, *_, legend = docs("ntp_associations").strip().splitlines()
    answers[CLI["ntp_associations"]] = (
        f"{header}\n ~192.0.2.7  {reference}  {stratum}  -  64  0  0.000  0.000  15937.\n{legend}\n"
    )
    ntp = ask()["ntp"]
    assert ntp["associations_complete"]
    peer, = ntp["peers"]
    assert peer["address"] == "192.0.2.7" and peer["reference"] == reference
    assert peer["stratum"] == stratum and peer["reach_octal"] == "0"
    assert peer["configured"] and not peer["selected"] and not peer["reachable"]
    assert peer["dispersion_ms"] == 15937.0


def test_ios_ntp_sys_peer_legend(public):
    answers, _, ask = public
    header = docs("ntp_associations").splitlines()[0]
    answers[CLI["ntp_status"]] = "Clock is synchronized, stratum 6, reference is 192.0.2.7\nclock offset is 0.0 msec\n"
    answers[CLI["ntp_associations"]] = (
        f"{header}\n"
        "*~192.0.2.7       127.127.1.1      5     55     64   377  9.503 390.522 63.524\n"
        " * sys.peer, # selected, + candidate, - outlyer, x falseticker, ~ configured\n"
    )
    report = ask()
    assert report["ntp"]["synchronized"] and report["ntp"]["associations_complete"]
    peer, = report["ntp"]["peers"]
    assert peer["selected"] and peer["configured"] and peer["reach_octal"] == "377"
    assert {"step": "ntp_associations", "reason": "unparsed"} not in report["missing"]


@pytest.mark.parametrize("priority_line,priority", [
    ("Priority 100 (default 100)", 100),
    ("Priority 110 (configured 110)", 110),
])
def test_ios_hsrp_group_54_priority(public, priority_line, priority):
    answers, _, ask = public
    answers[CLI["hsrp_detail"]] = lab("hsrp_group_54").replace("Priority 100 (default 100)", priority_line)
    hsrp = ask("hsrp_detail")["hsrp"]
    assert hsrp["complete"] and hsrp["status"] == "ok" and hsrp["unparsed_lines"] == 0
    record, = hsrp["records"]
    assert record["group"] == 54 and record["virtual_ip"] == "192.0.2.54"
    assert record["priority"] == priority


def test_health_partial_keeps_memory_and_warns_about_version(public):
    answers, calls, ask = public
    answers[CLI["version"]] = lab("version").replace("15.9(3)M12", "15.9(3)M99")
    answers[CLI["cpu"]] += "\n--More--"
    answers[CLI["ntp_associations"]] = docs("ntp_associations").splitlines()[0]
    report = ask(enabled=[q for q in HEALTH if q != "environment"])
    assert report["warnings"][0]["code"] == "firmware_untested"
    assert report["verdict"] == "incomplete" and "memory" in report
    assert {item["step"]: item["reason"] for item in report["missing"]} == {
        "cpu": "truncated", "environment": "permission_denied", "ntp_associations": "unparsed",
    }
    assert CLI["environment"] not in calls


@pytest.mark.parametrize("query,key", [("hsrp_detail", "hsrp"), ("vrrp_detail", "vrrp"),
                                        ("object_tracking", "object_tracking")])
def test_detail_empty_and_documented_record(public, query, key):
    answers, _, ask = public
    empty = ask(query)
    assert empty["ok"] and empty["complete"] and empty[key]["records"] == []
    answers[CLI[query]] = docs(query)
    report = ask(query)
    item, = report[key]["records"]
    assert report["complete"], report[key]
    if query == "hsrp_detail":
        assert item["hold_time"] == "4 sec" and item["state_changes"] == 1 and item["tracked_objects"][0]["id"] == 8
    elif query == "vrrp_detail":
        assert item["master_down_interval"] == "3.531 sec" and item["tracked_objects"][0]["decrement"] == 15
    else:
        assert item["ip_sla_id"] == 1 and item["latest_return_code"] == "over threshold"
    answers[CLI[query]] += "\n--More--"
    assert not ask(query)["complete"]


def test_sla_failure_and_header_only_switch(public):
    answers, _, ask = public
    report = ask("ip_sla_statistics")
    item, = report["ip_sla"]["records"]
    assert report["complete"] and item["id"] == 69 and item["return_code"] == "Timeout"
    assert item["latest_rtt_ms"] is None and item["successes"] == 0 and item["failures"] > 0
    answers[CLI["ip_sla_statistics"]] = lab("ip_sla_statistics", "d-iosvl2")
    report = ask("ip_sla_statistics")
    assert report["ok"] and report["status"] == "empty" and report["ip_sla"]["records"] == []


def test_device_refusal_and_admin_scope(public):
    answers, calls, ask = public
    refused = ask("log_history", log_window())
    assert not refused["ok"] and refused["status"] == "permission_denied"
    calls.clear()
    for query, params, enabled in (
        ("log_history", log_window(), ["log_history"]),
        ("log_history", log_window(interface="Gi0/2"), None),
        ("cpu", {}, ["clock", "log_history", "cpu"]),
        (None, None, None),
    ):
        assert "message" in ask(query, params, admin=True, enabled=enabled)
    assert not calls


def test_buffer_filter_and_redaction_before_pagination(public):
    answers, calls, ask = public
    legacy = (REAL_IOS / "iosv_15.9.3M12/log_messages.admin.txt").read_text()
    answers[CLI["clock"]] = lab("clock").replace("Nov 20 2026", "Nov 8 2026")
    answers[CLI["log_history"]] = legacy
    window = log_window("2026-11-08", "22:12:22", "22:12:25", severity="errors", interface="Gi0/1")
    report = ask("log_history", window, admin=True)
    assert report["ok"] and report["log_history"]["selected_messages"] == 1
    assert "%LINK-3-UPDOWN:" in report["untrusted_device_output"]
    assert calls == ["show version", "show clock", "show logging"]

    answers[CLI["clock"]] = lab("clock")
    window = log_window("2026-11-19", severity="notifications")
    reports = []
    for secret in ("az", "bx"):
        answers[CLI["log_history"]] = lab("log_history", role="admin").rstrip() + (
            f"\n*Nov 19 22:00:01.500: %PARSER-5-CFGLOG_LOGGEDCMD: User:fixture logged command: key 0 {secret}\n"
        )
        reports.append(ask("log_history", window, admin=True, max_bytes=12000))
    assert reports[0]["content_sha256"] == reports[1]["content_sha256"]
    assert "key <REDACTED>" in reports[0]["untrusted_device_output"]
    assert not reports[0]["complete"] and reports[0]["log_history"]["unreadable_lines"] > 0
    page = ask("log_history", window, admin=True, max_bytes=1000)
    calls.clear()
    remaining = ask("log_history", window, admin=True, offset=page["next_offset"], content_sha256=page["content_sha256"])
    assert remaining["log_history"] == page["log_history"] and not calls


def test_ios_audit_snmp_values_are_absent_from_the_snapshot(public):
    answers, calls, ask = public
    window = log_window("2026-11-19", "17:03:00", "22:01:00")
    original = lab("log_history", role="admin").rstrip()
    snapshots = []
    for auth_value, priv_value in (("authZ9", "privZ9"), ("ax", "px")):
        answers[CLI["log_history"]] = original + (
            "\n*Nov 19 22:00:01.500: %PARSER-5-CFGLOG_LOGGEDCMD: User:fixture logged command: "
            f"snmp-server user observer readers v3 auth sha {auth_value} priv aes 128 {priv_value}\n"
        )
        first = ask("log_history", window, admin=True, max_bytes=1000)
        assert first["next_offset"] is not None
        pages = [first["untrusted_device_output"]]
        page = first
        count = calls.count(CLI["log_history"])
        while page["next_offset"] is not None:
            page = ask("log_history", window, admin=True, max_bytes=1000,
                       offset=page["next_offset"], content_sha256=first["content_sha256"])
            pages.append(page["untrusted_device_output"])
        assert calls.count(CLI["log_history"]) == count
        snapshots.append((first["content_sha256"], "".join(pages)))
    assert snapshots[0] == snapshots[1]
    assert "%PARSER-5-CFGLOG_LOGGEDCMD:" in snapshots[0][1]
    assert all(value not in snapshots[0][1] for value in ("authZ9", "privZ9"))


@pytest.mark.parametrize("query", ["hsrp_detail", "vrrp_detail"])
def test_ios_gateway_authentication_continuation_is_absent_from_the_snapshot(public, query):
    answers, _, ask = public
    measured_empty = lab(query)
    example = docs(query).replace("  Authentication MD5, key-string\n", "")
    snapshots = []
    for value in ("fhrpZ9", "xz"):
        answers[CLI[query]] = measured_empty + example + (
            "  Authentication MD5\n"
            f"    Unrecognized detail: {value}\n"
            "  Virtual MAC address is 0000.5e00.0101\n"
        )
        reply = ask(query)
        assert reply["ok"] and not reply["complete"]
        snapshots.append((reply["content_sha256"], reply["untrusted_device_output"]))
    assert snapshots[0] == snapshots[1]
    assert "fhrpZ9" not in snapshots[0][1]
    assert "Virtual MAC address" in snapshots[0][1]


def test_ios_gateway_pager_on_hidden_continuation_marks_capture_truncated(public):
    answers, _, ask = public
    answers[CLI["hsrp_detail"]] = docs("hsrp_detail") + (
        "  Authentication MD5\n    Unrecognized detail: fixtureHidden --More--"
    )
    reply = ask("hsrp_detail")
    assert reply["ok"] and not reply["complete"]
    assert reply["status"] == "truncated"
    assert "fixtureHidden" not in reply["untrusted_device_output"]


def test_ios_gateway_last_page_is_not_a_verified_capture(public):
    answers, _, ask = public
    answers[CLI["hsrp_detail"]] = docs("hsrp_detail") * 5
    reply = ask("hsrp_detail", max_bytes=1000)
    assert reply["next_offset"] is not None and not reply["complete"]
    while reply["next_offset"] is not None:
        reply = ask("hsrp_detail", max_bytes=1000, offset=reply["next_offset"],
                    content_sha256=reply["content_sha256"])
    assert reply["ok"] and not reply["complete"]


def test_ios_ntp_without_peers_is_a_successful_empty_read(public):
    answers, _, ask = public
    assert not answers[CLI["ntp_associations"]].strip()
    reply = ask("ntp_associations")
    assert reply["ok"] and reply["status"] == "empty" and reply["complete"]


@pytest.mark.parametrize("start,end,complete", [
    ("09:00:00", "10:00:00", True),
    ("09:00:00", "10:00:01", False),
    ("13:00:00", "14:00:00", False),
    ("07:59:59", "10:00:00", False),
    ("08:00:00", "10:00:00", False),
])
def test_ios_history_requires_a_buffer_older_than_start_and_a_captured_end(public, start, end, complete):
    answers, _, ask = public
    clock = lab("clock")
    answers[CLI["clock"]] = "10:00:00.000" + " " + clock.split(" ", 1)[1]
    original = lab("log_history", role="admin").splitlines()
    captured = next(line for line in original if line.startswith("*Nov 19 ") and "%SYS-5-" in line)
    answers[CLI["log_history"]] = original[0] + "\n" + "*Nov 20 08:00:00.000: %" + captured.split(": %", 1)[1] + "\n"
    reply = ask("log_history", log_window("2026-11-20", start, end), admin=True)
    assert reply["ok"]
    assert reply["log_history"]["buffer_start"] == "2026-11-20T08:00:00"
    assert reply["complete"] is complete
    assert reply["log_history"]["complete"] is complete
