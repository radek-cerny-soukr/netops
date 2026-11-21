"""Ruckus diagnostics through MCP, the Helper proxy and the real engine over fixture PTY responses."""

from pathlib import Path

import pytest

from test_g108_ruckus import G107, public, unleashed  # noqa: F401

FIXTURES = Path(__file__).parent / "fixtures" / "ruckus_g109"
PROFILE = "ruckus_unleashed"
QUERIES = {
    "system_info": "show sysinfo",
    "access_points": "show ap all",
    "ethernet_info": "show ethinfo",
    "events_activities": "show events-activities",
    "mesh_topology": "show mesh topology",
    "rogue_devices": "show rogue-devices",
}
AP = "00:00:5e:00:53:01"


def capture(command):
    return (FIXTURES / (command.replace(" ", "_") + ".out")).read_text()


@pytest.fixture
def device(public, wire, monkeypatch):
    answers = {command: capture(command) for command in QUERIES.values()}
    sent = []
    unleashed(monkeypatch, answers, sent)
    return public(queries=QUERIES), answers, sent


def test_health_reports_current_role_links_resources_and_recorded_reboot(device):
    call, _, sent = device
    result = call("triage_health", target="r610")
    assert result["verdict"] == "no_fault_in_checked_data"
    assert result["firmware_support"]["status"] == "tested"
    assert result["checked"] == list(QUERIES)[:-1]
    assert sent == list(QUERIES.values())[:-1]
    chain = result["chain"]
    assert chain["resources"]["memory"] == {"used_kb": 236464, "free_kb": 234492,
                                            "used_percent": 51, "free_percent": 49}
    assert chain["master"]["macs"] == [AP]
    assert chain["mesh_topology"] == []
    assert chain["reported_ap_count"] == 1
    assert [(p["interface"], p["physical_link"], p["speed"]) for p in chain["ethernet"]["ports"]] == [
        ("eth0", "up", "1000Mbps"), ("eth1", "down", "1000Mbps")]
    ap = chain["access_points"][0]
    assert (ap["mesh"], ap["poe_mode"], ap["active_wired_ports"]) == ("Disabled", "802.3at", ["eth0"])
    assert ap["last_reported_restart"] == {"time": "2026-10-08T08:33:43", "reason": "power cycle detect"}
    assert ap["last_reported_rejoin"] == {"time": "2026-10-08T08:33:41", "reason": "AP Restart : power cycle detect"}
    assert {(r["width_mhz"], r["channel"], r["tx_power"]) for r in ap["radios"]} == {(40, 56, "Full"), (20, 11, "Full")}


@pytest.mark.parametrize("dedicated", [False, True], ids=["radio-ap", "dedicated-master"])
def test_health_requires_radio_blocks_on_radio_serving_ap(device, dedicated):
    call, answers, _ = device
    command = QUERIES["access_points"]
    before_radios, _, radio_and_lan = answers[command].partition("      Radio a/n:\n")
    _, after_radios = radio_and_lan.split("      Override global ap-model", 1)
    answers[command] = before_radios + "      Override global ap-model" + after_radios
    if dedicated:
        answers[command] = answers[command].replace("Model= r610", "Model= r750")
        sysinfo = QUERIES["system_info"]
        answers[sysinfo] = answers[sysinfo].replace("Model= r610", "Model= r750")
        answers[sysinfo] += "Dedicated Master:\n  Status= Enabled\nSmart Redundancy:\n  Status= Disabled\n"
    result = call("triage_health", target="r610")
    assert result["chain"]["access_points"][0]["radios"] == []
    if dedicated:
        assert result["verdict"] == "no_fault_in_checked_data"
    else:
        assert result["verdict"] == "incomplete"
        assert any(item["step"] == "access_points" and item["reason"] == "incomplete" and item["mac"] == AP
                   for item in result["missing"])


def test_health_keeps_facts_on_refused_and_incomplete_reads_and_warns_on_new_build(device):
    call, answers, _ = device
    answers["show ethinfo"] = (G107 / "ap_mac_absent.out").read_text().split("\n", 1)[1]
    answers["show ap all"] = answers["show ap all"].replace("Status= Disabled", "Unrecognized mesh output")
    answers["show sysinfo"] = answers["show sysinfo"].replace("build 27", "build 999")
    result = call("triage_health", target="r610")
    assert result["verdict"] == "incomplete"
    assert result["firmware_support"]["status"] == "untested"
    assert result["warnings"][0]["code"] == "firmware_untested"
    assert result["chain"]["resources"]["memory"]["used_percent"] == 51
    assert result["chain"]["access_points"][0]["last_reported_restart"]["reason"] == "power cycle detect"
    assert {item["step"] for item in result["missing"]} == {"ethernet_info", "access_points"}


def test_health_without_identity_enrollment_is_refused_before_transport(public, wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, {}, sent)
    call = public(queries=("access_points",))
    refused = call("triage_health", target="r610", refused=True)
    assert refused["data"]["field"] == "enabled_queries"
    assert sent == []


def test_rogues_distinguish_device_lists_and_require_all_sections(device):
    call, answers, _ = device
    def read():
        return call("ssh_read", target="r610", platform=PROFILE, query="rogue_devices")["wifi"]
    result = read()
    assert result["complete"]
    assert (result["active_count"], result["known_count"], result["blocked_count"]) == (2, 0, 0)
    assert all(row["list"] == "active" and row["type"] == "AP" for row in result["records"])
    command = QUERIES["rogue_devices"]
    answers[command] = answers[command].split("User Blocked Rogue Devices:")[0]
    result = read()
    assert not result["complete"] and result["incomplete"] and len(result["records"]) == 2

    answers[command] = "\n".join(line for line in capture(command).splitlines()
                                 if not line.startswith(" ")) + "\n"
    result = read()
    assert result["complete"] and result["records"] == []


def test_retained_activities_and_truncated_record(device):
    call, answers, _ = device
    def read():
        return call("ssh_read", target="r610", platform=PROFILE, query="events_activities")["wifi"]
    result = read()
    assert result["complete"] and len(result["records"]) == 5
    assert result["records"][0]["message"].startswith("Activities= Radio [5G]")
    assert "last reboot reason [power cycle detect]" in result["records"][2]["message"]
    answers[QUERIES["events_activities"]] = answers[QUERIES["events_activities"]].rsplit("    Activities=", 1)[0]
    result = read()
    assert not result["complete"] and result["unparsed_count"] == 1
    assert result["records"][-1]["message"] is None


def test_empty_activities_value_is_unparsed(device):
    call, answers, _ = device
    command = QUERIES["events_activities"]
    answers[command] = answers[command].rsplit("    Activities=", 1)[0] + "    Activities=\n"
    result = call("ssh_read", target="r610", platform=PROFILE, query="events_activities")["wifi"]
    assert not result["complete"] and result["unparsed_count"] == 1
    assert len(result["records"]) == 5 and result["records"][-1]["message"] is None


@pytest.mark.parametrize("query", ["events_activities", "events"])
def test_health_reports_mesh_disconnect_without_rejoin(public, wire, monkeypatch, query):
    history_command = "show events-activities" if query == "events_activities" else "show events"
    queries = {key: command for key, command in QUERIES.items() if key != "events_activities"}
    queries[query] = history_command
    answers = {command: capture(command) for command in QUERIES.values()}
    incident = (FIXTURES / "mesh_disconnect_vendor.out").read_text()
    answers[history_command] = answers[QUERIES["events_activities"]].replace(
        "Last 300 Events/Activities:\n", "Last 300 Events/Activities:\n" + incident, 1)
    sent = []
    unleashed(monkeypatch, answers, sent)
    result = public(queries=queries)("triage_health", target="r610")
    assert history_command in sent and result["sources"][query]["query"] == query
    assert result["chain"]["mesh_disconnect_events"] == [{
        "time": "2026-10-08T08:35:01", "severity": "Medium",
        "ap": "AP[mesh-ap 00:00:5e:00:53:02]", "root_ap": "AP[root-ap 00:00:5e:00:53:01]",
    }]


def test_vendor_topology_has_root_and_mesh_signal_and_preserves_partial_data(device):
    call, answers, _ = device
    command = QUERIES["mesh_topology"]
    answers[command] = (FIXTURES / "mesh_topology_vendor.out").read_text()
    def read():
        return call("ssh_read", target="r610", platform=PROFILE, query="mesh_topology")["wifi"]
    result = read()
    assert result["complete"]
    assert [(row["role"], row["mac"], row["uplink_db"]) for row in result["records"]] == [
        ("root", AP, None), ("mesh", "00:00:5e:00:53:02", 36)]
    answers[command] = answers[command].rsplit("    IP Address=", 1)[0]
    partial = read()
    assert not partial["complete"] and partial["incomplete"]
    assert partial["records"][1]["ip"] is None


def test_smart_redundancy_names_both_endpoints_and_masks_secret(device):
    call, answers, _ = device
    command = QUERIES["system_info"]
    # Dedicated Master and Smart Redundancy, Unleashed 200.15 CLI Reference pp. 67–68.
    answers[command] += (
        "Dedicated Master:\n  Status= Enabled\nSmart Redundancy:\n"
        "  Status= Enabled\n  Local Connect Status= Active\n  Peer IP Address= 192.0.2.6\n"
        "  Peer Connect Status = Standby\n  Shared Secret= fixture dummy secret\n"
    )
    result = call("triage_health", target="r610")
    assert result["chain"]["master"]["smart_redundancy"] == {
        "enabled": "Enabled", "local_status": "Active", "peer_status": "Standby", "peer_ip": "192.0.2.6"}
    output = call("ssh_read", target="r610", platform=PROFILE, query="system_info")["untrusted_device_output"]
    assert "fixture dummy secret" not in output
    answers[command] = answers[command].replace("  Peer Connect Status = Standby\n", "")
    incomplete = call("triage_health", target="r610")
    assert incomplete["verdict"] == "incomplete"
    assert incomplete["chain"]["master"]["smart_redundancy"]["local_status"] == "Active"


def test_health_reports_missing_redundancy_for_dedicated_master(device):
    call, answers, _ = device
    answers[QUERIES["system_info"]] += "Dedicated Master:\n  Status= Enabled\n"
    result = call("triage_health", target="r610")
    assert result["chain"]["master"]["dedicated"] == {"enabled": "Enabled"}
    assert result["chain"]["master"]["smart_redundancy"] is None
    assert result["verdict"] == "incomplete"
    assert any(item["step"] == "system_info" and item["reason"] == "incomplete"
               and "Smart Redundancy" in item["detail"] for item in result["missing"])
