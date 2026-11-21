"""Public IOS XE G72 reads with an SSH transport fed from CLI captures."""

import asyncio
from contextlib import nullcontext
import json
from pathlib import Path
import re

import pytest

from netops import worker
from netops_helper import engine, proxy, server
from test_proxy_contracts import _device, _egress, _inventory, _write


PROFILE = "cisco_xe"
FIXTURES = Path(__file__).parent / "fixtures"
LAB = FIXTURES / "real/cisco_xe/iolxe_17.18.2_g72"
IOL_NTP = FIXTURES / "real/cisco_xe/iolxe_17.18.2/ntp_associations.txt"
DOCS = FIXTURES / "docs/cisco_xe/g72"
LEGACY_LOG = FIXTURES / "real/cisco_ios/iosv_15.9.3M12/log_messages.admin.txt"
HEALTH = ("version", "cpu", "memory", "environment", "platform_resources", "ntp_status", "ntp_associations")
DETAIL = ("hsrp_detail", "vrrp_detail", "object_tracking", "ip_sla_statistics")
LOG = "show logging"
COMMANDS = {
    "version": "show version", "cpu": "show processes cpu", "memory": "show processes memory",
    "environment": "show environment all", "platform_resources": "show platform resources",
    "ntp_status": "show ntp status", "ntp_associations": "show ntp associations", "clock": "show clock",
    "hsrp_detail": "show standby", "vrrp_detail": "show vrrp", "object_tracking": "show track",
    "ip_sla_statistics": "show ip sla statistics", "log_messages": LOG,
}


def lab(query, node="d-iolxe", role="ro"):
    return (LAB / f"{node}-{role}-{query}.out").read_text()


def docs(query):
    return (DOCS / f"{query}.out").read_text()


def command(query):
    return COMMANDS[query]


@pytest.fixture
def public(tmp_path, monkeypatch):
    answers = {command(query): lab(query) for query in (*HEALTH, *DETAIL, "clock", "log_messages")}
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

    def transport(auth, platform, cli, **kwargs):
        assert platform == PROFILE
        calls.append(cli)
        result = answers[cli]
        return result if isinstance(result, tuple) else (0, result)

    original_exec = engine._exec_read
    monkeypatch.setattr(engine, "_exec_read", transport)
    bridge = worker.HelperBridge()

    def ask(tool, args, *, admin=False, enabled=None):
        if enabled is None:
            enabled = ["clock", "log_history"] if admin else [*HEALTH, *DETAIL, "clock", "log_history"]
        section = {
            "account_role": "admin-bounded" if admin else "read-only", "ssh_platform": PROFILE,
            "device_types": ["router"], "enabled_queries": enabled,
            "read_inventory": {"interfaces": ["Ethernet0/1", "Gi1/0/1"]},
            "egress": {**_egress(), "tcp_ports": [22]},
            "rate_limit": {"requests": 60, "window_seconds": 60},
        }
        if admin:
            section["role_boundary"] = "catalogue"
        _write(path, _inventory(_device(section, PROFILE)))
        result = asyncio.run(bridge.call(server.mcp, tool, {"target": "device-a", **args}))
        if "structuredContent" in result:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])

    return answers, calls, ask, original_exec


def read(public, query, parameters=None, *, admin=False, enabled=None, **options):
    return public[2]("ssh_read", {"platform": PROFILE, "query": query,
                                  "parameters": parameters or {}, **options}, admin=admin, enabled=enabled)


def test_health_lab_resources_and_missing_hardware_reads(public):
    result = public[2]("triage_health", {})
    assert "ok" in result, result
    assert result["ok"] and not result["complete"] and result["verdict"] == "incomplete"
    assert result["identity"]["uptime"] in lab("version")
    cpu = result["cpu"]
    expected = re.search(r"seconds: (\d+)%/(\d+)%; one minute: (\d+)%; five minutes: (\d+)%", lab("cpu"))
    assert (cpu["five_seconds_percent"], cpu["interrupt_percent"], cpu["one_minute_percent"],
            cpu["five_minutes_percent"]) == tuple(map(int, expected.groups()))
    assert cpu["five_seconds_minus_five_minutes_pp"] == int(expected[1]) - int(expected[4])
    assert result["memory"]["Processor"]["total_bytes"] == 549395184
    assert result["ntp"] == {"enabled": False, "synchronized": False, "peers": [], "associations_complete": True}
    assert {item["step"]: item["reason"] for item in result["missing"]} == {
        "environment": "permission_denied", "platform_resources": "permission_denied",
    }
    assert public[1] == list(map(command, HEALTH))


def test_health_hardware_and_ntp_examples(public):
    for query in ("environment", "platform_resources", "ntp_status", "ntp_associations"):
        public[0][command(query)] = docs(query)
    result = public[2]("triage_health", {})
    assert result["complete"] and result["verdict"] == "fault_found", result["missing"]
    assert [item["celsius"] for item in result["environment"]["temperatures"]] == [25, 35]
    assert result["environment"]["power_supplies"][0] == {"slot": "1A", "state": "No Input Power"}
    assert result["platform_resources"]["resources"][1]["usage"] == "2701MB(69%)"
    selected, = (peer for peer in result["ntp"]["peers"] if peer["selected"])
    assert selected["reach_octal"] == "377" and selected["successful_polls"] == 8
    assert selected["offset_ms"] == 11.18
    assert result["ntp"]["synchronized"] and result["ntp"]["offset_ms"] == 0.0


@pytest.fixture
def ntp_public(public, monkeypatch):
    answers, calls, ask, original_exec = public
    monkeypatch.setattr(engine, "_exec_read", original_exec)
    monkeypatch.setattr(engine, "host_key_line", lambda *args: "fixture-host-key")
    monkeypatch.setattr(engine, "_paced_connection", lambda *args: nullcontext())

    def open_ssh(address, port, login, credential, key, cli, **kwargs):
        calls.append(cli)
        return engine.core_ssh.Result(0, answers[cli].encode(), "", "", "")

    monkeypatch.setattr(engine.core_ssh, "run_command", open_ssh)
    return answers, ask


@pytest.mark.parametrize("legend,minus_candidate,plus_candidate", [
    ("iol", False, True), ("docs", True, False), ("absent", True, False),
])
def test_ntp_candidates_follow_legend(ntp_public, legend, minus_candidate, plus_candidate):
    answers, ask = ntp_public
    header, unselected, plus, primary, documented_legend = docs("ntp_associations").splitlines()
    # Derive an extra peer from the Cisco example and replay it with each source legend.
    minus = plus.replace("+~198.51.100.33", "-~198.51.100.34")
    legends = {"iol": IOL_NTP.read_text().splitlines()[-1], "docs": documented_legend, "absent": ""}
    answers[command("ntp_associations")] = "\n".join((header, unselected, plus, minus, primary, legends[legend]))
    result = ask("triage_health", {})
    peers = {peer["selection_mark"]: peer for peer in result["ntp"]["peers"]}
    assert peers["-"]["candidate"] is minus_candidate and not peers["-"]["selected"]
    assert peers["+"]["candidate"] is plus_candidate and not peers["+"]["selected"]
    assert peers["*"]["selected"] and not peers["*"]["candidate"]
    assert not peers[""]["candidate"]
    assert result["ntp"]["associations_complete"] is (legend != "absent")


def test_ntp_native_iol_associations_are_complete(ntp_public):
    answers, ask = ntp_public
    answers[command("ntp_associations")] = IOL_NTP.read_text()
    result = ask("triage_health", {})
    assert result["ntp"]["associations_complete"], result["missing"]
    peer, = result["ntp"]["peers"]
    assert peer["address"] == "198.51.100.123" and peer["dispersion_ms"] == 15937.0
    assert not peer["candidate"] and not peer["selected"]


def test_health_partial_source_and_unenrolled_queries(public):
    public[0][command("cpu")] = lab("cpu") + "\n--More--"
    public[0][command("ntp_associations")] = docs("ntp_associations").splitlines()[0] + "\n"
    result = public[2]("triage_health", {}, enabled=[query for query in HEALTH if query != "environment"])
    missing = {item["step"]: item["reason"] for item in result["missing"]}
    assert missing["cpu"] == "truncated" and missing["ntp_associations"] == "unparsed"
    assert missing["environment"] == "permission_denied" and command("environment") not in public[1]
    assert not result["complete"] and "memory" in result


def test_health_unverified_identity_stops_and_new_firmware_warns(public):
    public[0]["show version"] = lab("version").replace("17.18.02", "18.09.02").replace("17.18.2", "18.9.2")
    result = public[2]("triage_health", {})
    assert "ok" in result, result
    assert result["ok"] and result["warnings"][0]["code"] == "firmware_untested"
    assert "cpu" in result
    public[0]["show version"] = lab("environment")
    public[1].clear()
    result = public[2]("triage_health", {})
    assert "ok" in result, result
    assert result["ok"] is False and result["verdict"] == "incomplete"
    assert public[1] == ["show version"]


@pytest.mark.parametrize("query,key", [
    ("hsrp_detail", "hsrp"), ("vrrp_detail", "vrrp"), ("object_tracking", "object_tracking"),
])
def test_empty_gateway_or_tracking(public, query, key):
    result = read(public, query)
    assert "ok" in result, result
    assert result["ok"] and result["status"] == "empty" and result["complete"]
    assert result[key]["records"] == []


def test_empty_with_ssh_client_close_or_unexpected_device_stderr(public, monkeypatch):
    monkeypatch.setattr(engine, "_exec_read", public[3])
    monkeypatch.setattr(engine, "host_key_line", lambda *args: "fixture-host-key")
    monkeypatch.setattr(engine, "_paced_connection", lambda *args: nullcontext())
    device_stderr = b""

    def open_ssh(address, port, login, credential, key, cli, **kwargs):
        close_notice = lab("standby_client_close").replace("host01", address).encode()
        pq_notice = b"** WARNING: connection is not using a post-quantum key exchange algorithm.\n"
        body = public[0][cli].encode()
        return engine.core_ssh.Result(0, body, "", "", "", pq_notice + close_notice + device_stderr)

    monkeypatch.setattr(engine.core_ssh, "run_command", open_ssh)
    empty = read(public, "hsrp_detail")
    assert empty["ok"] and empty["complete"] and empty["status"] == "empty"
    device_stderr = b"Unexpected channel failure\n"
    failed = read(public, "hsrp_detail")
    assert not failed["ok"] and not failed["complete"] and failed["status"] == "unparsed"
    device_stderr = b""
    public[0][LOG] = lab("log_messages", role="admin")
    filtered = read(public, "log_history", log_window(interface="Ethernet0/1"), admin=True)
    assert filtered["ok"] and filtered["log_history"]["selected_messages"] == 0


def test_hsrp_transitions_timers_tracking_and_short_secret(public):
    public[0]["show standby"] = docs("hsrp_detail").replace("Authentication MD5, key-string", "Authentication text ab")
    result = read(public, "hsrp_detail")
    assert "ok" in result, result
    assert result["ok"] and result["complete"]
    entry, = result["hsrp"]["records"]
    assert (entry["group"], entry["state"], entry["state_changes"], entry["last_state_change"]) == (
        94, "Standby", 1, "01:06:09")
    assert (entry["hello_time"], entry["hold_time"]) == ("1 sec", "4 sec")
    assert entry["tracked_objects"][0]["id"] == 8
    assert "Authentication <REDACTED>" in result["untrusted_device_output"]
    assert "Authentication text ab" not in json.dumps(result)


@pytest.mark.parametrize("sample", ["vrrp_detail", "vrrp3_detail"])
def test_vrrp_timers_and_object_tracking(public, sample):
    public[0]["show vrrp"] = docs(sample)
    result = read(public, "vrrp_detail")
    assert "ok" in result, result
    assert result["ok"] and result["complete"]
    entry, = result["vrrp"]["records"]
    if sample == "vrrp_detail":
        assert (entry["master_down_interval"], entry["tracked_objects"][0]["decrement"]) == ("3.531 sec", 15)
    else:
        assert (entry["address_family"], entry["state_change_reason"]) == ("IPv4", "VRRP_TRACK_UP")


def test_tracking_sla_association_and_device_denial(public):
    public[0]["show track"] = docs("object_tracking")
    result = read(public, "object_tracking")
    assert "ok" in result, result
    assert result["ok"] and result["complete"]
    item, = result["object_tracking"]["records"]
    assert (item["ip_sla_id"], item["latest_return_code"], item["tracked_by"]) == (
        1, "over threshold", ["HSRP Ethernet0/1 3"])
    public[0]["show track"] = lab("object_tracking", node="d-iolxe-l2")
    refused = read(public, "object_tracking")
    assert not refused["ok"] and not refused["complete"] and refused["status"] == "permission_denied"


def test_sla69_statistics_and_l2_no_operations(public):
    result = read(public, "ip_sla_statistics")
    assert "ok" in result, result
    assert result["ok"] and result["complete"]
    item, = result["ip_sla"]["records"]
    assert item["id"] == 69 and item["return_code"] == "OK" and item["latest_rtt_ms"] == 4
    assert (item["successes"], item["failures"]) == (27, 0)
    public[0]["show ip sla statistics"] = lab("ip_sla_statistics", node="d-iolxe-l2")
    result = read(public, "ip_sla_statistics")
    assert "ok" in result, result
    assert result["ok"] and result["status"] == "empty" and result["ip_sla"]["records"] == []


@pytest.mark.parametrize("query,key,body,missing", [
    ("hsrp_detail", "hsrp", "hsrp_detail", "Hello time"),
    ("vrrp_detail", "vrrp", "vrrp_detail", "Master Down interval"),
    ("object_tracking", "object_tracking", "object_tracking", "State is Down"),
    ("ip_sla_statistics", "ip_sla", None, "Number of failures"),
])
def test_cut_at_line_boundary_preserves_partial_records(public, query, key, body, missing):
    text = docs(body) if body else lab(query)
    public[0][command(query)] = "".join(line for line in text.splitlines(keepends=True) if missing not in line)
    result = read(public, query)
    assert "ok" in result, result
    assert result["ok"] and not result["complete"] and result["status"] == "incomplete"
    assert len(result[key]["records"]) == 1


def log_window(date="2026-11-19", start="00:00:00", end="23:59:59", **filters):
    return {"begin_date": date, "begin_time": start, "end_date": date, "end_time": end, **filters}


def test_logged_events_and_coverage_from_lab(public):
    public[0][LOG] = lab("log_messages", role="admin")
    result = read(public, "log_history", log_window(severity="notifications"), admin=True)
    expected = [line for line in public[0][LOG].splitlines() if re.match(
        r"^[*.]?Nov\s+19 \d\d:\d\d:\d\d\.\d+:\s*%[A-Z_]+-[0-5]-", line)]
    assert "ok" in result, result
    assert result["ok"] and result["untrusted_device_output"].splitlines() == expected
    assert result["log_history"]["selected_messages"] == len(expected) > 0
    assert result["log_history"]["archive_correlation"] == "external_archive_unavailable"
    assert not result["log_history"]["requested_start_covered"] and not result["complete"]
    assert public[1] == ["show version", "show clock", LOG]


@pytest.mark.parametrize("cli", [
    "standby 7 authentication text {}",
    "standby 7 authentication md5 key-string 0 {}",
    "vrrp 7 authentication text {}",
    "key 7 {}",
    "password 0 {}",
    "secret 0 {}",
    "community {} RO",
    "snmp-server community {} RO",
    "tacacs-server host 192.0.2.4 key {}",
    "radius server lab key 0 {}",
])
@pytest.mark.parametrize("event", [
    "%PARSER-5-CFGLOG_LOGGEDCMD: User:reader logged command:",
    "%AAA-5-COMMAND: Executed command:",
])
@pytest.mark.parametrize("profile", ["cisco_ios", "cisco_xe"])
def test_ios_command_audit_logs_are_masked_before_hash(public, profile, event, cli):
    results = []
    secrets = ("synthetic-ALPHA", "synthetic-BRAVO")
    for secret in secrets:
        line = f"Nov 19 22:00:01.500: {event} {cli.format(secret)}"
        body = lab("log_messages", role="admin").rstrip() + "\n" + line + "\n"
        if profile == "cisco_xe":
            public[0][LOG] = body
            result = read(public, "log_history", log_window(severity="notifications"), admin=True)
        else:
            from dataclasses import replace
            from conftest import _target

            auth = replace(_target(profile, "log_messages"), enabled_queries=("log_messages",))
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(engine, "_exec_read", lambda a, p, cli, **kw:
                              (0, LEGACY_LOG.with_name("version.txt").read_text() if cli == "show version" else body))
                result = engine.ssh_read(auth, profile, "log_messages", {}, 0, 12_000)
        assert result["ok"], result
        output = result["untrusted_device_output"]
        assert secret not in output and event in output
        assert "<REDACTED>" in output
        results.append(result)
    for field in ("untrusted_device_output", "content_sha256"):
        assert results[0][field] == results[1][field]


def test_event_window_threshold_and_interface_filters_are_intersected(public):
    # This older IOS lab capture uses the same classic local link-event wire format.
    public[0][LOG] = LEGACY_LOG.read_text().replace("GigabitEthernet0/", "GigabitEthernet1/0/")
    public[0]["show clock"] = lab("clock").replace("Nov 19 2026", "Nov  8 2026")
    filters = log_window("2026-11-08", "22:12:22", "22:12:25", severity="errors", interface="Gi1/0/1")
    result = read(public, "log_history", filters, admin=True)
    assert "ok" in result, result
    assert result["ok"] and result["log_history"]["selected_messages"] == 1
    assert "GigabitEthernet1/0/1," in result["untrusted_device_output"]
    assert "%LINK-3-UPDOWN:" in result["untrusted_device_output"]
    assert "%LINEPROTO-" not in result["untrusted_device_output"]


def test_log_device_denial_and_clock_failure(public):
    refused = read(public, "log_history", log_window())
    assert not refused["ok"] and not refused["complete"] and refused["status"] == "permission_denied"
    public[0][LOG] = lab("log_messages", role="admin")
    public[0]["show clock"] = lab("environment")
    result = read(public, "log_history", log_window(), admin=True)
    assert "ok" in result, result
    assert result["ok"] and not result["complete"]
    assert result["log_history"]["clock_reason"] == "permission_denied"
    assert result["log_history"]["scanned_lines"] > 0
    assert result["log_history"]["selected_messages"] == 0


def test_log_continuation_keeps_filters_and_clock_snapshot(public):
    public[0][LOG] = lab("log_messages", role="admin")
    window = log_window(severity="notifications")
    page = read(public, "log_history", window, admin=True, max_bytes=1000)
    assert page["ok"] and page["next_offset"] and not page["complete"]
    remainder = read(public, "log_history", window, admin=True, max_bytes=12000,
                     offset=page["next_offset"], content_sha256=page["content_sha256"])
    assert remainder["ok"] and remainder["pagination_source"] == "cached"
    assert remainder["log_history"] == page["log_history"] and not remainder["complete"]
    assert public[1] == ["show version", "show clock", LOG]


@pytest.mark.parametrize("params,enabled", [
    (log_window(interface="Ethernet0/2"), None),
    (log_window(severity="5"), None),
    (log_window(start="17:00:00", end="16:59:59"), None),
    (log_window(), ["log_history"]),
])
def test_log_proxy_refuses_invalid_filters_and_unenrolled_clock(public, params, enabled):
    result = read(public, "log_history", params, admin=True, enabled=enabled)
    assert "message" in result
    assert not public[1]


def test_admin_enrollment_stays_bounded(public):
    result = public[2]("triage_health", {}, admin=True)
    assert "message" in result
    assert public[1] == []
