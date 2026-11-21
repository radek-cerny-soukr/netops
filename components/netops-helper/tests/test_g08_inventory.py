"""G08 (1.0.12): device inventory (FG-17) and managed FortiSwitch overview (FG-24).

Real RO captures of the IT-case 80F, FortiOS 8.0.2 build0251, 2026-11-17 (anonymised, see the README next to
the fixtures). The SSH transport and the REST GET are faked; the captured text/JSON goes through the real
engine, parser and REST envelope code.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from conftest import FORTIOS_STATUS, PASSWORD, _target
from netops_helper import engine, fortigate_tables, wifi_rest as r
from netops_helper.auth import EgressPolicy
from netops_helper.query_catalog.fortinet import QUERIES
from netops_helper.read_policy import _validate_query_command

REAL = Path(__file__).parent / "fixtures/real/fortinet/fortigate80f_8.0.2_build0251/g08_20261117"
CAPTURES = json.loads((REAL / "captures.json").read_text())
DEVICES = CAPTURES["user_devices"]
TOKEN = "synthetic-rest-token-canary-12345"
CERT = b"synthetic DER certificate"


def document(name):
    return json.loads((REAL / (name + ".json")).read_text())


# ---------------------------------------------------------------- FG-17: diagnose user device list

def _fake_ssh(monkeypatch, body):
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        return 0, FORTIOS_STATUS if command == engine._IDENTITY_COMMAND else body

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    return sent


def _read(offset=0, max_bytes=16_000, digest=None):
    return engine.ssh_read(_target("fortinet", "user_devices"), "fortinet", "user_devices", None,
                           offset, max_bytes, digest)


def test_catalogue_entry_is_the_fixed_read_only_command():
    query = QUERIES["user_devices"]
    assert (query.command, dict(query.slots), query.high_volume) == ("diagnose user device list", {}, True)
    _validate_query_command("fortinet", query.command)
    assert "devices" in query.description and "no longer connected" in query.description


def test_ssh_read_lists_every_device_with_mac_ip_host_os_interface_and_last_seen(monkeypatch):
    sent = _fake_ssh(monkeypatch, DEVICES)
    answer = _read(max_bytes=48_000)
    assert answer["ok"] is True and answer["next_offset"] is None
    assert sent[-1] == "diagnose user device list"
    devices = answer["devices"]
    assert (devices["state"], devices["total_devices"], devices["unreadable_lines"]) == ("ok", 18, 0)
    assert len(devices["devices"]) == 18 and len({d["mac"] for d in devices["devices"]}) == 18
    tablet = next(d for d in devices["devices"] if d["hostname"] == "host05")
    assert tablet == {
        "mac": "00:00:5e:00:53:05", "ip": "198.51.100.7", "ipv6": None, "hostname": "host05", "os": "iPadOS",
        "os_version": "26.6.2", "vendor": "Apple", "device_type": "Tablet", "family": "iPad",
        "hardware_version": "Air", "interface": "host01", "created_seconds_ago": 745608, "seen_seconds_ago": 12}
    access_point = next(d for d in devices["devices"] if d["hostname"] == "host06")
    assert (access_point["ip"], access_point["ipv6"], access_point["interface"], access_point["family"]) == (
        "203.0.113.3", "2001:db8:1::2", "ap-mgmt", "FortiAP")
    # Devices without an address or host name stay in the inventory with null fields.
    bare = devices["devices"][0]
    assert (bare["mac"], bare["ip"], bare["hostname"], bare["vendor"], bare["interface"]) == (
        "00:00:5e:00:53:01", None, None, "Fortinet", "internal4")
    assert bare["seen_seconds_ago"] == 163279
    assert PASSWORD not in json.dumps(answer)


def test_device_not_seen_for_days_is_still_listed_and_found_by_host_name(monkeypatch):
    _fake_ssh(monkeypatch, DEVICES)
    devices = _read(max_bytes=48_000)["devices"]["devices"]
    named = {d["hostname"]: d for d in devices if d["hostname"]}
    assert {"host02", "host03", "host04", "host05", "host06"} <= set(named)
    stale = [d for d in devices if d["seen_seconds_ago"] > 7 * 24 * 3600]
    assert stale and all(d["created_seconds_ago"] >= d["seen_seconds_ago"] for d in devices)


def test_pages_carry_their_own_devices_once_with_whole_output_counts(monkeypatch):
    _fake_ssh(monkeypatch, DEVICES)
    pages = [_read(max_bytes=1_000)]
    while pages[-1]["next_offset"] is not None:
        pages.append(_read(pages[-1]["next_offset"], 1_000, pages[0]["content_sha256"]))
    assert len(pages) > 2
    assert {page["devices"]["total_devices"] for page in pages} == {18}
    macs = [d["mac"] for page in pages for d in page["devices"]["devices"]]
    assert len(macs) == len(set(macs)) == 18


def test_cut_output_is_incomplete_not_a_shorter_inventory():
    cut = DEVICES[:DEVICES.index("scan off", DEVICES.index("00:00:5e:00:53:03")) + len("scan off")] + "\n"
    result = fortigate_tables.user_devices(cut, 0, len(cut.encode()))
    assert result["state"] == "incomplete"
    assert (result["total_devices"], result["devices_without_seen_line"]) == (3, 1)


def test_unknown_line_shape_makes_the_read_incomplete():
    text = DEVICES.replace("    created 3762s  seen 827s  host01\n", "    created 3762s  seen 827s  host01\n    something new\n")
    result = fortigate_tables.user_devices(text, 0, len(text.encode()))
    assert (result["state"], result["unreadable_lines"], result["total_devices"]) == ("incomplete", 1, 18)


def test_refused_command_is_a_cli_error_without_devices(monkeypatch):
    _fake_ssh(monkeypatch, CAPTURES["refused_parse_error"])
    answer = _read()
    assert answer["ok"] is False and answer["error_code"] == "device_cli_error"
    assert "devices" not in answer


def test_other_queries_get_no_devices_object(monkeypatch):
    _fake_ssh(monkeypatch, DEVICES)
    answer = engine.ssh_read(_target("fortinet", "arp_table"), "fortinet", "arp_table", None, 0, 16_000)
    assert "devices" not in answer


# ---------------------------------------------------------------- FG-24: managed FortiSwitch overview

def _auth(**changes):
    values = dict(fortios_rest_token=TOKEN, fortios_rest_certificate_sha256=hashlib.sha256(CERT).hexdigest(),
                  egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(443,)))
    values.update(changes)
    return dataclasses.replace(_target("fortinet", "system_status"), **values)


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    r._rates.clear()


@pytest.fixture
def http(monkeypatch):
    """Fake socket/TLS/HTTP below wifi_rest.get; answers per path from the captured documents."""
    answers = {r.SWITCH_STATUS: (200, document("managed_switch_status")),
               r.SWITCH_HEALTH: (200, document("managed_switch_health"))}
    paths = []
    peer = MagicMock()
    peer.getpeercert.return_value = CERT
    context = MagicMock()
    context.wrap_socket.return_value = peer
    monkeypatch.setattr(r.ssl, "SSLContext", lambda *a: context)
    monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: MagicMock())

    def connection(*args, **kwargs):
        conn = MagicMock()

        def request(method, path, headers):
            paths.append((method, path))
            status, body = answers[path]
            response = conn.getresponse.return_value
            response.status = status
            response.chunked = False
            response.getheader.side_effect = lambda key, default=None: default
            response.read1.side_effect = [json.dumps(body).encode(), b""]
        conn.request.side_effect = request
        return conn
    monkeypatch.setattr(r.http.client, "HTTPSConnection", connection)
    return answers, paths


def test_overview_lists_both_switches_without_serials_from_two_get_reads(http):
    answers, paths = http
    result = engine.fortiswitch_overview(_auth())
    assert result["ok"] is True
    assert paths == [("GET", r.SWITCH_STATUS), ("GET", r.SWITCH_HEALTH)]
    assert result["records"] == [
        {"serial": "S000SSSS00000001", "switch_id": "S000SSSS00000001", "status": "Connected", "state": "Authorized",
         "ip": "192.0.2.2", "os_version": "S224EP-v8.0.1-build069,260728 (GA)", "fortilink_interface": "fortilink",
         "join_time_local": "Sun Nov 15 10:27:33 2026", "config_sync_error": False,
         "uptime_seconds": 746220, "health": "good"},
        {"serial": "S000SSSS00000002", "switch_id": "S000SSSS00000002", "status": "Connected", "state": "Authorized",
         "ip": "192.0.2.3", "os_version": "S224EP-v8.0.1-build069,260728 (GA)", "fortilink_interface": "fortilink",
         "join_time_local": "Sun Nov 15 10:27:34 2026", "config_sync_error": False,
         "uptime_seconds": 746160, "health": "good"},
    ]
    assert result["counts"] == {"switches": 2, "up": 2, "not_connected": 0}
    assert [source["endpoint"] for source in result["sources"]] == [r.SWITCH_STATUS, r.SWITCH_HEALTH]
    assert TOKEN not in json.dumps(result) and "ports" not in json.dumps(result["records"])


def test_switch_that_is_not_connected_is_counted_and_has_no_uptime(http):
    # Derived from the real capture: the lab cannot unplug a switch in a read-only task, so the second switch's
    # status text is replaced and its health row dropped; the tool only compares status with "Connected".
    answers, _ = http
    status = document("managed_switch_status")
    status["results"][1].update(status="Disconnected", connecting_from="0.0.0.0")
    answers[r.SWITCH_STATUS] = (200, status)
    health = document("managed_switch_health")
    health["results"] = health["results"][:1]
    answers[r.SWITCH_HEALTH] = (200, health)
    result = engine.fortiswitch_overview(_auth())
    assert result["counts"] == {"switches": 2, "up": 1, "not_connected": 1}
    second = result["records"][1]
    assert (second["status"], second["ip"], second["uptime_seconds"], second["health"]) == (
        "Disconnected", "0.0.0.0", None, None)


def test_refused_health_read_keeps_the_connection_view(http):
    answers, _ = http
    answers[r.SWITCH_HEALTH] = (403, {})
    result = engine.fortiswitch_overview(_auth())
    assert result["ok"] is True and len(result["records"]) == 2
    assert result["health_missing"] == {"reason": "rest_unavailable", "error_code": "authorization_failed",
                                        "http_status": 403, "failed_step": r.SWITCH_HEALTH}
    assert {row["uptime_seconds"] for row in result["records"]} == {None}


def test_refused_status_read_returns_no_switches(http):
    answers, paths = http
    answers[r.SWITCH_STATUS] = (401, {})
    result = engine.fortiswitch_overview(_auth())
    assert result["ok"] is False and result["records"] == []
    assert (result["error_code"], result["http_status"]) == ("authentication_failed", 401)
    assert paths == [("GET", r.SWITCH_STATUS)]


def test_incomplete_or_foreign_envelope_is_not_a_switch_list(http):
    answers, _ = http
    status = document("managed_switch_status")
    status["results"] = {"not": "a list"}
    answers[r.SWITCH_STATUS] = (200, status)
    result = engine.fortiswitch_overview(_auth())
    assert result["ok"] is False and result["error_code"] == "unparsed_envelope" and result["records"] == []
    with pytest.raises(r.RestError, match="unparsed"):
        r.parse(r.SWITCH_STATUS, {**document("managed_switch_status"), "vdom": "other"})


@pytest.mark.parametrize("missing", ["serial", "status"])
def test_switch_list_with_missing_required_fields_is_not_counted(http, missing):
    answers, paths = http
    status = document("managed_switch_status")
    del status["results"][1][missing]
    answers[r.SWITCH_STATUS] = (200, status)
    result = engine.fortiswitch_overview(_auth())
    assert not result["ok"] and result["error_code"] == "invalid_response"
    assert result["records"] == [] and "counts" not in result
    assert paths == [("GET", r.SWITCH_STATUS)]


@pytest.mark.parametrize(("field", "value"), [("serial", 13), ("serial", " "), ("status", ""), ("status", "\r")])
def test_switch_list_with_malformed_required_fields_is_not_counted(http, field, value):
    answers, _ = http
    status = document("managed_switch_status")
    status["results"][1][field] = value
    answers[r.SWITCH_STATUS] = (200, status)
    result = engine.fortiswitch_overview(_auth())
    assert not result["ok"] and result["error_code"] == "invalid_response"
    assert result["records"] == [] and "counts" not in result


def test_without_rest_enrollment_the_tool_says_so_and_reads_nothing(http):
    _, paths = http
    result = engine.fortiswitch_overview(_auth(fortios_rest_token=None))
    assert result["ok"] is False and result["error_code"] == "unsupported" and paths == []


def test_switch_paths_are_fixed_get_endpoints_only():
    assert {r.SWITCH_STATUS, r.SWITCH_HEALTH} <= r.PATHS
    for path in (r.SWITCH_STATUS + "?mkey=x", "/api/v2/monitor/switch-controller/managed-switch/port-stats"):
        assert not r._allowed_path(path)
    with pytest.raises(ValueError, match="policy_scope"):
        r.get(_auth(), r.SWITCH_STATUS, method="POST")
