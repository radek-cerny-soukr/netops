"""SENSORS-CRASHLOG (1.0.12): FortiGate hardware sensors (FG-19) and crash log (FG-20).

Real RO captures of the fortigate-ha 80F, FortiOS 8.0.2 build0251, 2026-11-17 (anonymised, see the README next to the
fixtures). Only the SSH transport is faked; the captured text goes through the real engine, redaction, paging and
parser code. Mutations of the real capture are marked as such.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import FORTIOS_STATUS, PASSWORD, _target
from netops_helper import engine, fortios_vdom, triage_health
from netops_helper.query_catalog.fortinet import QUERIES
from netops_helper.read_policy import _validate_query_command

FIXTURES = Path(__file__).parent / "fixtures/real/fortinet/fortigate80f_8.0.2_build0251"
CAPTURES = json.loads((FIXTURES / "sensors_crashlog_20261117/captures.json").read_text())
SENSORS = CAPTURES["hardware_sensors"]
CRASH = CAPTURES["crash_log"]
# The RO account's real refusal of a command (FIREWALL-INVENTORY capture, same device and account): `command parse error`, -61.
REFUSED = json.loads((FIXTURES / "firewall_inventory_20261117/captures.json").read_text())["refused_parse_error"]
TRAILER = "Crash log interval is 3600 seconds\nMax crash log line number: 16384\n"


def _fake_ssh(monkeypatch, body, rc=0):
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        return (0, FORTIOS_STATUS) if command == engine._IDENTITY_COMMAND else (rc, body)

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    return sent


def _read(query, offset=0, max_bytes=16_000, digest=None):
    return engine.ssh_read(_target("fortinet", query), "fortinet", query, None, offset, max_bytes, digest)


# ---------------------------------------------------------------- catalogue

@pytest.mark.parametrize("query,command,high_volume,empty_allowed", [
    ("hardware_sensors", "execute sensor detail", False, False),
    ("crash_log", "diagnose debug crashlog read", True, True),
    ("config_error_log", "diagnose debug config-error-log read", False, True),
])
def test_catalogue_entries_are_fixed_read_only_commands(query, command, high_volume, empty_allowed):
    entry = QUERIES[query]
    assert (entry.command, dict(entry.slots), entry.high_volume, entry.empty_allowed) == (
        command, {}, high_volume, empty_allowed)
    _validate_query_command("fortinet", entry.command)
    # Device-wide data: labelled `device` in multi-VDOM and refused to a per-VDOM administrator.
    assert fortios_vdom.DATA_SCOPES[query] == "device"
    assert query in fortios_vdom.VDOM_ADMIN_REFUSED_QUERIES


# ---------------------------------------------------------------- FG-19: execute sensor detail

def test_ssh_read_lists_the_sensors_the_80f_reports(monkeypatch):
    sent = _fake_ssh(monkeypatch, SENSORS)
    answer = _read("hardware_sensors")
    assert answer["ok"] is True and answer["next_offset"] is None
    assert sent[-1] == "execute sensor detail"
    sensors = answer["sensors"]
    assert (sensors["state"], sensors["total_sensors"], sensors["unreadable_lines"]) == ("ok", 5, 0)
    assert sensors["alarms"] == [] and sensors["absent"] == ["PSU [2]"]
    by_name = {sensor["name"]: sensor for sensor in sensors["sensors"]}
    assert list(by_name) == ["PSU [1]", "PSU [2]", "CPU ON-DIE Temperature", "MV1548 Temperature",
                             "MV1680 Temperature"]
    assert by_name["PSU [1]"] == {
        "index": 1, "name": "PSU [1]", "reading": "OK", "value": None, "unit": None, "absent": False,
        "type": "PSU status (10/0)", "sensor_status": "Power working Well", "alarm": False, "thresholds": {}}
    assert (by_name["PSU [2]"]["sensor_status"], by_name["PSU [2]"]["alarm"]) == ("Power absent(PSU not present)", False)
    cpu = by_name["CPU ON-DIE Temperature"]
    assert (cpu["value"], cpu["unit"], cpu["sensor_status"], cpu["alarm"], cpu["thresholds"]) == (
        69.3, "C", "Normal", False, {"upper_critical": 110.0})
    # Measured: two temperature sensors are printed without an Alarm line; alarm stays unknown, not "no".
    assert (by_name["MV1548 Temperature"]["value"], by_name["MV1548 Temperature"]["alarm"]) == (88.0, None)
    assert sensors["sensors_without_alarm_line"] == 2
    assert PASSWORD not in json.dumps(answer)


def test_a_sensor_in_alarm_is_named():
    # Mutation of the real capture: the CPU sensor's Alarm line says Yes.
    head, tail = SENSORS.split("CPU ON-DIE Temperature", 1)
    text = head + "CPU ON-DIE Temperature" + tail.replace("Alarm                 : No", "Alarm                 : Yes", 1)
    result = triage_health.hardware_sensors(text, 0, len(text.encode()))
    assert (result["state"], result["alarms"]) == ("ok", ["CPU ON-DIE Temperature"])


@pytest.mark.parametrize("change", [
    lambda text: text.replace("    Type                  : Temperature (1/0)\n",
                              "    Type                  : Temperature (1/0)\nsomething new\n", 1),
    lambda text: text.replace("[HW monitor sensors]\n", "", 1),
    lambda text: text.replace("Upper critical        : 110.0", "Upper critical        : n/a", 1),
], ids=["unknown-line", "no-header", "unreadable-threshold"])
def test_an_unknown_shape_is_incomplete_not_a_shorter_list(change):
    text = change(SENSORS)
    assert text != SENSORS
    result = triage_health.hardware_sensors(text, 0, len(text.encode()))
    assert result["state"] == "incomplete" and result["total_sensors"] == 5


def test_refused_sensor_read_is_an_error_without_sensors(monkeypatch):
    _fake_ssh(monkeypatch, REFUSED)
    answer = _read("hardware_sensors")
    assert answer["ok"] is False and answer["error_code"] == "device_cli_error" and "sensors" not in answer


# ---------------------------------------------------------------- FG-20: diagnose debug crashlog read

def test_ssh_read_parses_the_whole_crash_history(monkeypatch):
    sent = _fake_ssh(monkeypatch, CRASH)
    answer = _read("crash_log", max_bytes=48_000)
    assert answer["ok"] is True
    assert sent[-1] == "diagnose debug crashlog read"
    rest = _read("crash_log", answer["next_offset"], 48_000, answer["content_sha256"])
    assert rest["ok"] is True and rest["next_offset"] is None
    log = answer["crash_log"]
    entries = log["entries"] + rest["crash_log"]["entries"]
    assert (log["state"], log["total_lines"], log["unreadable_lines"]) == ("ok", 606, 0)
    assert (log["interval_seconds"], log["max_lines"], log["full"]) == (3600, 16384, False)
    assert (log["first_time"], log["last_time"]) == ("2026-10-22 06:02:04", "2026-11-17 11:22:42")
    assert log["daemon_kills"][:2] == [
        {"daemon": "/bin/cloudapid", "count": 25, "nonzero_status": 0, "last_time": log["daemon_kills"][0]["last_time"]},
        {"daemon": "/bin/cu_acd", "count": 25, "nonzero_status": 0, "last_time": "2026-11-15 10:27:25"}]
    helper = next(item for item in log["daemon_kills"] if item["daemon"] == "/bin/cw_acd_helper")
    assert (helper["count"], helper["nonzero_status"]) == (11, 11)
    assert [entry["line"] for entry in entries] == list(range(1, 607))
    assert entries[0] == {"line": 1, "time": "2026-10-22 06:02:04",
                                 "text": "the killed daemon is /bin/sflowd: status=0x0"}
    segfault = next(entry for entry in entries if "signal 11 (Segmentation fault)" in entry["text"])
    assert segfault["time"] == "2026-11-13 20:08:20"


def test_pages_carry_their_own_entries_once_with_whole_log_counts(monkeypatch):
    _fake_ssh(monkeypatch, CRASH)
    pages = [_read("crash_log")]
    while pages[-1]["next_offset"] is not None:
        pages.append(_read("crash_log", pages[-1]["next_offset"], 16_000, pages[0]["content_sha256"]))
    assert len(pages) >= 4
    assert {page["crash_log"]["total_lines"] for page in pages} == {606}
    lines = [entry["line"] for page in pages for entry in page["crash_log"]["entries"]]
    assert lines == list(range(1, 607))


@pytest.mark.parametrize("body", [TRAILER, "", "\n"], ids=["trailer-only", "no-output", "newline"])
def test_an_empty_crash_log_is_a_successful_empty_read(monkeypatch, body):
    # trailer-only: mutation of the real capture (entries removed, trailer kept).
    _fake_ssh(monkeypatch, body)
    answer = _read("crash_log")
    assert answer["ok"] is True
    log = answer["crash_log"]
    assert (log["state"], log["total_lines"], log["entries"], log["daemon_kills"]) == ("empty", 0, [], [])


def test_an_unavailable_crash_log_is_an_error_never_empty(monkeypatch):
    _fake_ssh(monkeypatch, REFUSED)
    answer = _read("crash_log")
    assert answer["ok"] is False and answer["error_code"] == "device_cli_error" and "crash_log" not in answer


@pytest.mark.parametrize("query", ["crash_log", "config_error_log"])
@pytest.mark.parametrize("body", ["", "\n"], ids=["no-output", "newline"])
def test_a_failed_read_without_output_is_an_error_never_empty(monkeypatch, query, body):
    # Review: the log command fails (exit status 1, nothing on stdout) after a successful identity read.
    sent = _fake_ssh(monkeypatch, body, rc=1)
    answer = _read(query)
    assert sent[-1] == QUERIES[query].command
    assert answer["ok"] is False and answer["rc"] == 1 and answer["error_code"] == "device_cli_error"
    assert "crash_log" not in answer and "untrusted_device_output" not in answer


def test_a_cut_line_makes_the_crash_log_incomplete():
    # Mutation of the real capture: the output stops inside the last entry's time stamp.
    text = CRASH[:CRASH.index("606: 2026-11-17 11:2") + len("606: 2026-11-17 11:2")] + "\n"
    result = triage_health.crash_log(text, 0, len(text.encode()))
    assert (result["state"], result["total_lines"], result["unreadable_lines"]) == ("incomplete", 605, 1)
    assert result["interval_seconds"] is None


def test_a_log_at_its_line_limit_is_marked_full():
    text = "1: 2026-11-17 11:22:42 the killed daemon is /bin/sshd: status=0x100\n" \
           "Crash log interval is 3600 seconds\nMax crash log line number: 1\n"
    result = triage_health.crash_log(text, 0, len(text.encode()))
    assert (result["state"], result["full"], result["daemon_kills"][0]["nonzero_status"]) == ("ok", True, 1)


# ---------------------------------------------------------------- 413:FOS-10: diagnose debug config-error-log read

def test_the_real_empty_config_error_log_is_a_successful_read(monkeypatch):
    sent = _fake_ssh(monkeypatch, CAPTURES["config_error_log"])
    answer = _read("config_error_log")
    assert sent[-1] == "diagnose debug config-error-log read"
    assert answer["ok"] is True and answer["complete"] is True and "error_code" not in answer


def test_a_refused_config_error_log_is_an_error(monkeypatch):
    _fake_ssh(monkeypatch, REFUSED)
    answer = _read("config_error_log")
    assert answer["ok"] is False and answer["error_code"] == "device_cli_error"
