"""EOS-HEALTH (1.0.12, EP09/EP10): EOS log window reads and health/routing summaries.

Replays anonymized cEOS 4.36.1F output (fixtures/real/arista_eos/eos_health_ceos_4.36.1F) through engine.ssh_read with a
fake transport. Cut or malformed variants are derived from those real texts inside the tests.
"""
import json
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine, proxy
from netops_helper.auth import TargetAuth
from netops_helper.read_policy import render_read_query
from netops_helper.triage_health import eos_ntp_status
from test_proxy_contracts import DEVICE_SECRET, _assert_policy_error, _configure, _device, _inventory, _request, _section, _write

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
FIXTURES = FIXTURE_ROOT / "real/arista_eos/eos_health_ceos_4.36.1F"
CAPTURES = json.loads((FIXTURES / "index.json").read_text())
PLATFORM = "arista_eos"
INVENTORY = {"addresses": ("198.51.100.1", "203.0.113.101", "203.0.113.253")}
RANGE = {"begin_date": "2026-11-18", "begin_time": "12:23:00", "end_date": "2026-11-18", "end_time": "12:24:30",
         "severity": "informational"}


@pytest.fixture(autouse=True)
def _empty_page_cache():
    engine._SSH_PAGE_CACHE.clear()
    yield
    engine._SSH_PAGE_CACHE.clear()


def replay(monkeypatch, row, text=None, max_bytes=48000):
    query, parameters = row["query"], row["parameters"]
    command = render_read_query(PLATFORM, query, parameters, INVENTORY)[1]
    calls = []

    def read(_auth, platform, actual):
        assert platform == PLATFORM
        calls.append(actual)
        if actual == "show version":
            return 0, CAPTURES["version_ro"]["text"]
        assert actual == command
        return row["rc"], row["text"] if text is None else text

    monkeypatch.setattr(engine, "read_from_device", read)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    auth = replace(_target(PLATFORM, "version"), enabled_queries=("version", query), read_inventory=INVENTORY)
    result = engine.ssh_read(auth, PLATFORM, query, parameters, 0, max_bytes)
    assert calls[-1] == command
    return result


@pytest.fixture
def proxy_read(monkeypatch, tmp_path):
    for name in ("INVENTORY", "VAULT", "EGRESS_POLICY", "RUNNER"):
        monkeypatch.setattr(proxy, name, getattr(proxy, name))
    inventory, *_ = _configure(proxy, tmp_path)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    def read(row, *, text=None, parameters=None, refused=False, max_bytes=16000, all_pages=False):
        query = row["query"]
        section = dict(_section(), ssh_platform=PLATFORM, enabled_queries=[query],
                       read_inventory={**INVENTORY, "interfaces": ["Ethernet1/1", "Ethernet3", "Ethernet12", "Ethernet120"]})
        _write(inventory, _inventory(_device(section, PLATFORM)))
        calls = []

        def transport(_auth, platform, command):
            assert platform == PLATFORM
            calls.append(command)
            if command == "show version":
                return 0, CAPTURES["version_ro"]["text"]
            assert command == row["command"]
            return row["rc"], row["text"] if text is None else text

        monkeypatch.setattr(engine, "read_from_device", transport)
        params = row["parameters"] if parameters is None else parameters
        call = _request(1, "ssh_read", {"target": "device-a", "platform": PLATFORM, "query": query,
                                        "parameters": params})
        gateway = proxy.Proxy()
        if refused:
            _assert_policy_error(gateway, call)
            with pytest.raises(ValueError):
                render_read_query(PLATFORM, query, params, section["read_inventory"])
            assert not calls
            return
        forwarded = gateway.request(call)
        assert forwarded is not None, (query, params)
        args = json.loads(forwarded)["params"]["arguments"]
        auth = TargetAuth.decode(args["target"], args["auth_context"])
        outputs = [engine.ssh_read(auth, args["platform"], args["query"], args["parameters"], 0, max_bytes)]
        while all_pages and outputs[-1].get("next_offset") is not None:
            outputs.append(engine.ssh_read(auth, args["platform"], args["query"], args["parameters"],
                                           outputs[-1]["next_offset"], max_bytes, outputs[0]["content_sha256"]))
        assert calls == ["show version", row["command"]]
        return outputs if all_pages else outputs[0]

    return read


def test_rendered_commands_are_the_captured_commands():
    for key, row in CAPTURES.items():
        assert render_read_query(PLATFORM, row["query"], row["parameters"], INVENTORY)[1] == row["command"], key


@pytest.mark.parametrize("case", sorted(CAPTURES))
def test_real_eos_reads_are_complete(monkeypatch, case):
    row = CAPTURES[case]
    result = replay(monkeypatch, row)
    assert result["ok"] and result["rc"] == 0
    assert bool(result["untrusted_device_output"].strip()) == bool(row["text"].strip())


def test_log_range_counts_severity_and_port(monkeypatch):
    summary = replay(monkeypatch, CAPTURES["log_messages_range_ro"])["log_summary"]
    assert summary["state"] == "ok"
    assert summary["window"] == RANGE
    assert summary["total_messages"] == 11 and summary["unreadable_lines"] == 0
    assert summary["by_severity"]["notifications"] == 6 and summary["by_severity"]["informational"] == 5
    assert sum(summary["by_severity"].values()) == 11
    assert summary["by_interface"] == [{"interface": "Ethernet12", "messages": 6, "first_time": "Nov 18 12:23:26",
                                        "last_time": "Nov 18 12:23:56", "most_severe": "notifications"}]
    down = [entry for entry in summary["entries"] if entry["mnemonic"] == "UPDOWN"]
    assert [entry["text"].rsplit(" ", 1)[-1] for entry in down] == ["down", "up"]
    assert down[0]["facility"] == "LINEPROTO" and down[0]["severity"] == "notifications"
    assert down[0]["interfaces"] == ["Ethernet12"]
    assert summary["first_time"] == "Nov 18 12:23:25" and summary["last_time"] == "Nov 18 12:23:56"


def test_log_last_threshold_keeps_only_the_listed_severities(monkeypatch):
    summary = replay(monkeypatch, CAPTURES["log_last_warnings_ro"])["log_summary"]
    assert summary["window"] == {"minutes": "10", "severity": "warnings"}
    assert summary["total_messages"] == 3 and summary["by_severity"]["warnings"] == 3
    assert [item["interface"] for item in summary["by_interface"]] == ["Management0"]
    full = replay(monkeypatch, CAPTURES["log_messages_last_ro"])["log_summary"]
    assert full["total_messages"] == 14
    assert {item["interface"]: item["messages"] for item in full["by_interface"]} == {"Ethernet12": 6, "Management0": 3}


def test_long_log_window_is_capped_and_reported_truncated(proxy_read):
    pages = proxy_read(CAPTURES["log_last_2880_warnings_ro"], max_bytes=4096, all_pages=True)
    assert len(pages) > 1
    newest = CAPTURES["log_last_2880_warnings_ro"]["text"].splitlines()[-1]
    for result in pages:
        assert result["line_limit"] == {"max_lines": 200, "total_lines": 780, "returned_lines": 200, "truncated": True}
        summary = result["log_summary"]
        assert summary["state"] == "incomplete" and summary["total_messages"] == 200 and summary["unreadable_lines"] == 0
        assert summary["dropped_lines"] == 580 and summary["last_time"] == newest[:15]
    assert sum(len(page["log_summary"]["entries"]) for page in pages) == 200


@pytest.mark.parametrize("case", ["log_messages_last_ro", "log_messages_range_ro"])
def test_log_interface_filters_before_capping(proxy_read, case):
    row = CAPTURES[case]
    original = [line for line in row["text"].splitlines() if "Ethernet12" in line]
    assert len(original) == 6
    # Keep the captured port events at the beginning, followed by 201 derived events for a different port.
    lines = original + [original[-1].replace("Ethernet12", "Ethernet120")] * 201
    lines[0] += " password=" + DEVICE_SECRET
    result = proxy_read(row, text="\n".join(lines) + "\n", parameters={**row["parameters"], "interface": "Ethernet12"})
    summary = result["log_summary"]
    assert summary["state"] == "ok" and summary["total_messages"] == 6 and summary["dropped_lines"] == 0
    assert summary["window"]["interface"] == "Ethernet12"
    assert result["line_limit"]["total_lines"] == 6
    assert len(summary["entries"]) == 6 and all(entry["interfaces"] == ["Ethernet12"] for entry in summary["entries"])
    assert "Ethernet120" not in result["untrusted_device_output"] and DEVICE_SECRET not in json.dumps(result)


@pytest.mark.parametrize("case", ["log_messages_last_ro", "log_messages_range_ro"])
@pytest.mark.parametrize("interface", ["Ethernet1/1", "Ethernet3"])
def test_log_interface_uses_local_lldp_port(proxy_read, case, interface):
    fixture = FIXTURE_ROOT / "real/arista_eos/ceos_4.36.1F/log_messages.txt"
    lines = fixture.read_text().splitlines(keepends=True)
    messages = lines[156] + lines[161]
    # Adapt a real system message to include an interface name outside any local port field.
    incidental = lines[159].rstrip("\n") + ' (diagnostic label "Ethernet3")\n'
    row = CAPTURES[case]
    result = proxy_read(row, text=messages + incidental, parameters={**row["parameters"], "interface": interface})
    assert result["ok"]
    summary = result["log_summary"]
    if interface == "Ethernet1/1":
        assert summary["state"] == "empty" and summary["total_messages"] == 0
        assert result["untrusted_device_output"] == "" and summary["entries"] == []
    else:
        assert summary["state"] == "ok" and summary["total_messages"] == 2
        assert result["untrusted_device_output"] == messages
        assert [entry["mnemonic"] for entry in summary["entries"]] == ["NEIGHBOR_NEW", "NEIGHBOR_TIMEOUT"]
        assert all(entry["interfaces"] == ["Ethernet3"] for entry in summary["entries"])
        assert [item["interface"] for item in summary["by_interface"]] == ["Ethernet3"]


@pytest.mark.parametrize("interface", ["Ethernet13", "Ethernet12 | json"])
def test_log_interface_respects_eos_type_and_enrollment(proxy_read, interface):
    row = CAPTURES["log_messages_range_ro"]
    proxy_read(row, parameters={**row["parameters"], "interface": interface}, refused=True)


def test_log_interface_no_matches_is_empty(proxy_read):
    row = CAPTURES["log_messages_range_ro"]
    result = proxy_read(row, parameters={**row["parameters"], "interface": "Ethernet120"})
    assert result["ok"] and result["log_summary"]["state"] == "empty"
    assert result["untrusted_device_output"] == "" and result["log_summary"]["entries"] == []


def test_log_interface_unknown_line_is_accounted_for_without_returning_it(proxy_read):
    row = CAPTURES["log_messages_range_ro"]
    text = row["text"] + "unrecognized log line naming Ethernet12\n"
    result = proxy_read(row, text=text, parameters={**row["parameters"], "interface": "Ethernet12"})
    summary = result["log_summary"]
    assert summary["state"] == "incomplete" and summary["unreadable_lines"] == 1
    assert summary["total_messages"] == 6 and "unrecognized log line" not in result["untrusted_device_output"]


def test_empty_log_window_is_an_empty_successful_read(monkeypatch):
    result = replay(monkeypatch, CAPTURES["log_range_empty_ro"])
    assert result["ok"] and result["log_summary"]["state"] == "empty"
    assert result["log_summary"]["total_messages"] == 0


def test_unknown_log_line_makes_the_summary_incomplete(monkeypatch):
    row = CAPTURES["log_messages_range_ro"]
    lines = row["text"].splitlines()
    text = "\n".join(lines[:3] + ["   continuation of an unknown shape"] + lines[3:]) + "\n"
    summary = replay(monkeypatch, row, text)["log_summary"]
    assert summary["state"] == "incomplete" and summary["unreadable_lines"] == 1 and summary["total_messages"] == 11


def test_failed_window_read_is_not_an_empty_log(monkeypatch):
    row = CAPTURES["log_range_empty_ro"]
    result = replay(monkeypatch, {**row, "rc": 1}, "")
    assert not result["ok"] and result["error_code"] == "device_cli_error"


@pytest.mark.parametrize("parameters", [
    {"minutes": "0", "severity": "warnings"}, {"minutes": "10000", "severity": "warnings"},
    {"minutes": "010", "severity": "warnings"}, {"minutes": "10", "severity": "warning"},
    {"minutes": "10", "severity": "warnings | json"}, {"minutes": "10"},
])
def test_log_window_slots_are_typed(parameters):
    with pytest.raises(ValueError):
        render_read_query(PLATFORM, "log_messages_last", parameters, {})


@pytest.mark.parametrize("change", [
    {"begin_date": "2026-02-30"}, {"end_time": "24:00:00"}, {"begin_time": "12:23"}, {"end_date": "18/11/2026"},
    {"begin_date": "2026-11-18", "begin_time": "12:24:31"},
])
def test_log_range_slots_are_typed_and_ordered(change):
    with pytest.raises(ValueError):
        render_read_query(PLATFORM, "log_messages_range", {**RANGE, **change}, {})


def test_reversed_range_never_reaches_the_device(monkeypatch):
    # Measured: EOS prints nothing for a range ending before it begins; the Helper refuses it before any read.
    monkeypatch.setattr(engine, "read_from_device", lambda *args: pytest.fail("device read"))
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    auth = replace(_target(PLATFORM, "version"), enabled_queries=("version", "log_messages_range"))
    with pytest.raises(ValueError, match="must not end before it begins"):
        engine.ssh_read(auth, PLATFORM, "log_messages_range",
                        {**RANGE, "begin_time": "12:24:00", "end_time": "12:23:00"}, 0, 16000)


def test_proxy_accepts_the_same_log_slot_values():
    slots = proxy.READ_QUERY_SLOTS[PLATFORM]
    assert {"log_messages_last", "log_messages_range"} <= proxy.READ_QUERY_NAMES[PLATFORM]
    assert slots["log_messages_last"]["minutes"] == {"inventory": None, "kind": "eos_log_minutes"}
    for kind, good, bad in (("eos_log_minutes", "9999", "10000"), ("log_severity", "debugging", "debug"),
                            ("log_date", "2026-11-18", "2026-13-01"), ("log_time", "23:59:59", "23:60:00")):
        assert proxy._valid_typed_inventory_value(good, kind)
        assert not proxy._valid_typed_inventory_value(bad, kind)


def test_cpu_summary_reports_low_memory(monkeypatch):
    summary = replay(monkeypatch, CAPTURES["cpu_ro"])["cpu_summary"]
    assert summary["state"] == "ok" and summary["unreadable_lines"] == 0
    assert summary["load_average"] == [7.97, 7.67, 7.36]
    assert summary["tasks"]["total"] == 80 and summary["tasks"]["zombie"] == 0
    assert summary["cpu_percent"]["idle"] == 10.9 and summary["cpu_percent"]["user"] == 57.8
    assert summary["memory"] == {"total_mib": 20001.2, "free_mib": 467.6, "used_mib": 18352.2,
                                 "buff_cache_mib": 2255.7, "available_mib": 1649.0}
    assert summary["process_count"] == 80 and len(summary["top_processes"]) == 5
    assert summary["top_processes"][0]["command"] == "Etba" and summary["top_processes"][0]["cpu_percent"] == 6.7
    # Idle 10.9 % is above the 10 % limit; available memory 8.2 % of total is below its limit.
    assert [item["id"] for item in summary["findings"]] == ["F-EOS-MEMORY-LOW"]
    busy = CAPTURES["cpu_ro"]["text"].replace(" 10.9 id,", "  4.6 id,")  # derived: idle as captured at 12:18:41
    assert [item["id"] for item in replay(monkeypatch, CAPTURES["cpu_ro"], busy)["cpu_summary"]["findings"]] == [
        "F-EOS-CPU-BUSY", "F-EOS-MEMORY-LOW"]


def test_cut_cpu_snapshot_is_not_a_measurement(monkeypatch):
    row = CAPTURES["cpu_ro"]
    head = row["text"].split("    PID USER", 1)[0]
    assert replay(monkeypatch, row, head)["cpu_summary"] == {"state": "unparsed", "findings": []}
    lines = row["text"].splitlines()
    cut = "\n".join(lines[:-3] + [lines[-3][:30]]) + "\n"
    assert replay(monkeypatch, row, cut)["cpu_summary"]["state"] == "incomplete"


def test_cpu_snapshot_without_last_process_is_incomplete(proxy_read):
    row = CAPTURES["cpu_ro"]
    # Drop the last whole process row, with rc=0 and no truncation marker.
    cut = "\n".join(row["text"].rstrip().splitlines()[:-1]) + "\n"
    summary = proxy_read(row, text=cut)["cpu_summary"]
    assert summary["process_count"] == 79 and summary["tasks"]["total"] == 80
    assert summary["state"] == "incomplete"


def test_environment_supplies_warning_preserves_temperature_and_cooling(proxy_read):
    text = (FIXTURE_ROOT / "real/arista_eos/ceos_4.36.1F/environment.txt").read_text()
    # The captured warning sets rc=1 even though the following sections are available.
    row = {"query": "environment", "command": "show system environment all", "parameters": {}, "rc": 1, "text": text}
    result = proxy_read(row)
    assert result["rc"] == 1 and result["status"] == "transport_error"
    summary = result["environment_summary"]
    assert summary["state"] == "incomplete" and summary["power_supplies_present"] is False
    assert summary["temperature_status"] == summary["cooling_status"] == "Unknown"
    assert summary["action_on_overheat"] == "unknown" and summary["cooling_zones"] == 1


def test_bgp_summary_reports_active_and_established_peers(proxy_read):
    text = (FIXTURE_ROOT / "docs/arista_eos/bgp_summary.txt").read_text()
    row = {"query": "bgp_summary", "command": "show ip bgp summary", "parameters": {}, "rc": 0, "text": text}
    summary = proxy_read(row)["bgp_summary"]
    assert summary["state"] == "ok" and summary["by_state"] == {"Active": 1, "Established": 3}
    assert summary["unreadable_lines"] == 0
    active = next(peer for peer in summary["peers"] if peer["state"] == "Active")
    assert (active["neighbor"], active["remote_as"], active["vrf"], active["prefixes"]) == (
        "192.0.2.9", "65003", "default", None)


def test_truncated_established_bgp_row_preserves_the_peer_as_incomplete(proxy_read):
    text = (FIXTURE_ROOT / "docs/arista_eos/bgp_summary.txt").read_text().rstrip().rsplit(maxsplit=2)[0]
    row = {"query": "bgp_summary", "command": "show ip bgp summary", "parameters": {}, "rc": 0, "text": text}
    summary = proxy_read(row)["bgp_summary"]
    assert summary["state"] == "incomplete" and summary["unreadable_lines"] == 1
    assert summary["peers"][-1]["state"] == "Established" and summary["peers"][-1]["prefixes"] is None


def test_bgp_inactive_remains_not_applicable(proxy_read):
    text = (FIXTURE_ROOT / "real/arista_eos/ceos_4.36.1F/bgp_summary.txt").read_text()
    row = {"query": "bgp_summary", "command": "show ip bgp summary", "parameters": {}, "rc": 1, "text": text}
    result = proxy_read(row)
    assert result["status"] == result["bgp_summary"]["state"] == "not_applicable"
    assert result["bgp_summary"]["peers"] == []


def test_reload_cause_and_ntp_disabled(monkeypatch):
    cause = replay(monkeypatch, CAPTURES["reload_cause_ro"])["reload_cause_summary"]
    assert cause == {"state": "ok", "causes": ["The system rebooted due to unknown reasons."],
                     "recommended_action": [], "debugging_information_lines": 0, "other_sections": []}
    ntp = replay(monkeypatch, CAPTURES["ntp_status_ro"])["ntp_summary"]
    assert ntp["state"] == "ok" and ntp["enabled"] is False and ntp["findings"] == []
    text = CAPTURES["reload_cause_ro"]["text"].replace("Reload Cause:", "Reload Reason:")
    assert replay(monkeypatch, CAPTURES["reload_cause_ro"], text)["reload_cause_summary"]["state"] == "unparsed"


def test_ntp_documented_forms():
    # Documentation example (https://www.arista.com/en/um-eos/eos-switch-administration-commands), not a capture.
    synced = eos_ntp_status("synchronized to NTP server (192.0.2.62) at stratum 3\n"
                            "   time correct to within 66 ms\n   polling server every 1024 s\n")
    assert (synced["synchronized"], synced["server"], synced["stratum"], synced["findings"]) == (
        True, "192.0.2.62", 3, [])
    unsynced = eos_ntp_status("unsynchronised\n")
    assert unsynced["synchronized"] is False and unsynced["findings"][0]["id"] == "F-EOS-NTP-UNSYNC"
    assert eos_ntp_status("NTP status unknown\n")["state"] == "unparsed"


def test_ospf_neighbors_full_and_not_full(monkeypatch):
    row = CAPTURES["ospf_neighbors_ro"]
    summary = replay(monkeypatch, row)["ospf_summary"]
    assert summary["state"] == "ok" and summary["by_state"] == {"FULL": 4} and summary["findings"] == []
    assert [item["role"] for item in summary["neighbors"]] == ["DROTHER", "DROTHER", "DROTHER", "DR"]
    # Derived negative: the last adjacency still in INIT.
    lines = row["text"].splitlines()
    text = "\n".join(lines[:-1] + [lines[-1].replace("FULL/DR   ", "INIT      ")]) + "\n"
    stuck = replay(monkeypatch, row, text)["ospf_summary"]
    assert stuck["by_state"] == {"FULL": 3, "INIT": 1}
    assert [item["id"] for item in stuck["findings"]] == ["F-EOS-OSPF-NOT-FULL"]
    cut = "\n".join(lines[:-1] + [lines[-1][:40]]) + "\n"
    assert replay(monkeypatch, row, cut)["ospf_summary"]["state"] == "incomplete"


def test_ospf_two_ways_neighbors_from_live_capture(proxy_read):
    text = json.loads((FIXTURE_ROOT / "ospf_live20.json").read_text())["ceos"]["stdout"]
    summary = proxy_read(CAPTURES["ospf_neighbors_ro"], text=text)["ospf_summary"]
    assert summary["state"] == "ok" and summary["by_state"] == {"2WAY": 2, "FULL": 2}
    assert summary["unreadable_lines"] == 0 and summary["findings"] == []
    assert [(peer["neighbor_id"], peer["role"]) for peer in summary["neighbors"] if peer["state"] == "2WAY"] == [
        ("203.0.113.7", "DROTHER"), ("203.0.113.1", "DROTHER")]


def test_route_lookup_summaries(monkeypatch):
    ospf = replay(monkeypatch, CAPTURES["route_lookup_ospf_ro"])["route_lookup_summary"]
    assert ospf == {"state": "ok", "address": "198.51.100.1", "matched_prefix": "198.51.100.1/32",
                    "default_route": False, "unreadable_lines": 0,
                    "routes": [{"prefix": "198.51.100.1/32", "protocol": "ospf", "next_hop": "203.0.113.1",
                                "interface": "Vlan10"}]}
    connected = replay(monkeypatch, CAPTURES["route_lookup_connected_ro"])["route_lookup_summary"]
    assert connected["matched_prefix"] == "203.0.113.0/24" and connected["routes"][0]["protocol"] == "connected"
    assert connected["routes"][0]["interface"] == "Vlan10" and connected["default_route"] is False
    default = replay(monkeypatch, CAPTURES["route_lookup_default_ro"])["route_lookup_summary"]
    assert default["matched_prefix"] == "0.0.0.0/0" and default["default_route"] is True
    assert default["routes"][0]["protocol"] == "static"


def test_route_lookup_without_route_lines_is_not_a_match(monkeypatch):
    row = CAPTURES["route_lookup_ospf_ro"]
    legend = row["text"].split(" O        198", 1)[0]
    summary = replay(monkeypatch, row, legend)["route_lookup_summary"]
    assert summary["state"] == "empty" and summary["matched_prefix"] is None


def test_route_lookup_prefix_without_nexthop_is_incomplete(proxy_read):
    row = CAPTURES["route_lookup_ospf_ro"]
    # Drop the whole 'via' continuation and preserve the matching prefix line and rc=0.
    cut = "\n".join(line for line in row["text"].splitlines() if not line.lstrip().startswith("via ")) + "\n"
    summary = proxy_read(row, text=cut)["route_lookup_summary"]
    assert summary["state"] == "incomplete" and summary["unreadable_lines"] == 1
    assert summary["matched_prefix"] is None and summary["routes"] == []
