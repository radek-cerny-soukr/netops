"""wifi_triage over the measured FortiOS 8.0.2 Wi-Fi output: what it concludes and what it refuses to conclude."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from netops_helper import triage_health, wifi_parse
from netops_helper import triage_wifi as t

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 8, 20, 40, 0, tzinfo=timezone.utc)
STATUS = "Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)\nVirtual domain configuration: disable\n"
CLIENT = "00:00:5e:00:53:37"
AP2 = "FAPEXAMPLE0000002"
ALIAS = "fg"
RSSI = {"step": "client_rssi", "reason": "rest_token_not_enrolled", "detail": t.RSSI_DETAIL}


def fixture(name):
    return (FIXTURES / ("fortios_80f_802_wifi_" + name + ".txt")).read_text(encoding="utf-8")


def outputs(**changes):
    values = {
        "system_status": STATUS,
        # the measured ARP table, with the client behind 192.0.2.19 made the event client
        "arp_table": fixture("system_arp").replace("00:00:5e:00:53:32", CLIENT),
        "wifi_events": fixture("log_display_wireless"),
        "wifi_ap_status": fixture("wtp_status"),
        "wifi_vap_status": fixture("vap_status"),
        # the measured RF table belongs to access point 1; the client sat on access point 2
        "wifi_rf_analysis": fixture("rf_analysis_one").replace("FAPEXAMPLE0000001", AP2),
        "wifi_neighbors": fixture("scan"),
    }
    values.update(changes)
    return values


def run(values, mac=CLIENT, ip=None, refused=None):
    calls = []
    refused = refused or {}

    def read(query, parameters):
        calls.append((query, parameters))
        if query in refused:
            return {"ok": False, "reason": refused[query]}
        text = values[query]
        if query == "wifi_events":  # the Helper filters by MAC after redaction
            text = wifi_parse.filter_events_by_mac(text, parameters["mac_literal"])[0]
        return {"ok": True, "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest()}

    ticks = iter(NOW + timedelta(seconds=n) for n in range(100))
    return t.run(read, lambda: next(ticks), mac, ip, ALIAS, enabled_queries=tuple(values)), calls


def ids(result):
    return [item["id"] for item in result["findings"]]


def steps(result):
    return [item["step"] for item in result["missing"]]


def test_client_is_followed_from_events_to_ap_radio_vap_and_rf():
    result, calls = run(outputs())
    assert [query for query, _ in calls] == [
        "system_status", "wifi_events", "wifi_ap_status", "wifi_vap_status", "wifi_rf_analysis", "wifi_neighbors"]
    assert calls[1][1] == {"lines": "200", "mac_literal": CLIENT}
    assert calls[4][1] == {"wtp_id": AP2}
    chain = result["chain"]
    assert {k: chain["events"]["window"][k] for k in ("requested_lines", "device_found", "device_returned", "client_records", "undated_records")} == {"requested_lines": 200, "device_found": 211, "device_returned": 20,
                                         "client_records": 4, "undated_records": 0}
    last = chain["events"]["last_event"]
    assert (last["logdesc"], last["time"], last["channel"], last["ap"], last["radio"]) == (
        "Wireless client disassociated", "2026-11-08T20:28:53+01:00", 116, AP2, 2)
    assert chain["access_point"]["serial"] == AP2 and chain["access_point"]["state"] == "Connected"
    assert (chain["radio"]["radio"], chain["radio"]["channel"], chain["radio"]["chutil_percent"]) == (2, 116, 1)
    assert chain["vap"]["name"] == "ssid-17" and chain["vap"]["clients_online"] == 2
    assert chain["rf"] == {"channel": 116, "rssi_total": 73, "rf_score": 8, "overlap_ap": 1, "interfere_ap": 1,
                           "chan_utilization_percent": 0}
    assert chain["neighbors"]["same_channel"] == 0 and chain["neighbors"]["scan_entries"] == 32
    assert chain["last_logged_signal_dbm"] == -33
    assert result["identity"] == {"product": "FortiGate-80F", "version": "8.0.2", "build": "0251"}
    assert result["checked"] == ["system_status", "wifi_events", "wifi_ap_status", "wifi_vap_status",
                                 "wifi_rf_analysis", "wifi_neighbors"]


def test_a_last_event_disconnect_is_a_notice_and_the_verdict_is_never_healthy():
    result, _ = run(outputs())
    assert ids(result) == ["F-WIFI-CLIENT-DISCONNECTED"]
    assert result["findings"][0]["severity"] == "notice"
    assert result["findings"][0]["sources"][0]["query"] == "wifi_events"
    assert result["verdict"] == "incomplete"
    assert [h["id"] for h in result["hypotheses"]] == ["H-WIFI-EARLIER-ERROR"]
    assert "healthy" not in json.dumps(result).lower()


def test_without_rest_the_signal_and_the_switch_port_are_missing_with_a_stable_reason_and_the_next_step():
    result, _ = run(outputs())
    assert RSSI in result["missing"]
    assert any(m["step"] == "locate_endpoint" and "lldp_uplink" in m for m in result["missing"])
    assert any(m["step"] == "rf_data" for m in result["missing"])
    assert "enroll" in RSSI["detail"] and "REST token" in RSSI["detail"]
    assert "pending" not in json.dumps(result) and "not in this build" not in json.dumps(result)
    assert result["vantage"]["account"] == "read-only" and "RSSI" in result["vantage"]["does_not_see"]


def test_ip_is_resolved_through_arp_and_must_be_unambiguous():
    result, calls = run(outputs(), mac=None, ip="192.0.2.19")
    assert [q for q, _ in calls][:3] == ["system_status", "arp_table", "wifi_events"]
    assert {k: result["client"][k] for k in ("mac", "ip", "ip_source", "arp_interface")} == {"mac": CLIENT, "ip": "192.0.2.19", "ip_source": "argument", "arp_interface": "ssid-17"}
    unknown, calls = run(outputs(), mac=None, ip="192.0.2.99")
    assert [q for q, _ in calls] == ["system_status", "arp_table"]
    assert unknown["client"]["mac"] is None and unknown["verdict"] == "incomplete"
    assert [m["step"] for m in unknown["missing"]][:2] == ["arp_table", "wifi_events"]
    assert unknown["missing"][0]["reason"] == "ip_not_in_arp"
    twice = fixture("system_arp") + "192.0.2.19    0   00:00:5e:00:53:aa ssid-17\n"
    ambiguous, _ = run(outputs(arp_table=twice), mac=None, ip="192.0.2.19")
    assert ambiguous["missing"][0]["reason"] == "ambiguous" and ambiguous["client"]["mac"] is None
    incomplete = fixture("system_arp").replace("00:00:5e:00:53:32", "00:00:00:00:00:00")
    assert run(outputs(arp_table=incomplete), mac=None, ip="192.0.2.19")[0]["missing"][0]["reason"] == "ip_not_in_arp"


def test_a_client_without_events_in_the_window_leaves_everything_after_it_unknown():
    result, calls = run(outputs(), mac="00:00:5e:00:53:aa")
    assert [q for q, _ in calls] == ["system_status", "wifi_events"]
    assert result["findings"] == [] and result["verdict"] == "incomplete"
    assert steps(result)[:2] == ["client_events", "ap_radio"]
    assert result["missing"][0]["reason"] == "not_in_window" and "history window (20 records)" in result["missing"][0]["detail"]
    assert result["chain"]["access_point"] is None and result["chain"]["radio"] is None


def test_ap_not_connected_is_a_fault():
    text = fixture("wtp_status").replace("connection-state : Connected", "connection-state : Disconnected")
    result, _ = run(outputs(wifi_ap_status=text))
    assert "F-WIFI-AP-NOT-CONNECTED" in ids(result) and result["verdict"] == "fault_found"
    assert next(f for f in result["findings"] if f["id"] == "F-WIFI-AP-NOT-CONNECTED")["fact"] == "connection-state: Disconnected"


@pytest.mark.parametrize("query,fixture_name,line,field", [
    ("wifi_ap_status", "wtp_status", "    connection-state : Connected\n", "connection-state"),
    ("wifi_ap_status", "wtp_status", "    oper-chan        : 116\n", "oper-chan"),
    ("wifi_vap_status", "vap_status", "    downup_oper      : up\n", "downup_oper"),
])
def test_missing_decisive_field_is_not_a_fault(query, fixture_name, line, field):
    original = fixture(fixture_name)
    assert line in original
    result, _ = run(outputs(**{query: original.replace(line, "")}))
    assert result["verdict"] == "incomplete"
    assert any(field in item.get("detail", "") for item in result["missing"])


def test_vap_down_and_radio_not_operating_are_faults():
    down = fixture("vap_status").replace("downup_oper      : up", "downup_oper      : down")
    result, _ = run(outputs(wifi_vap_status=down))
    assert ids(result) == ["F-WIFI-CLIENT-DISCONNECTED", "F-WIFI-VAP-DOWN"] and result["verdict"] == "fault_found"
    block = fixture("wtp_status").split("WTP: FAPEXAMPLE0000002")[1]
    off = fixture("wtp_status").replace(block, block.replace("oper-chan        : 116", "oper-chan        : 0"))
    result, _ = run(outputs(wifi_ap_status=off))
    assert "F-WIFI-RADIO-NOT-OPERATING" in ids(result) and result["verdict"] == "fault_found"
    assert "rf_analysis" in steps(result)  # no operating channel, so no RF row to read


def test_latest_client_error_event_is_a_fault():
    only_error = "\n".join(line for line in fixture("log_display_wireless").split("\n")
                           if not line.startswith(("12:", "13:", "14:")))
    result, _ = run(outputs(wifi_events=only_error))
    assert ids(result)[0] == "F-WIFI-CLIENT-ERROR" and result["verdict"] == "fault_found"
    assert result["chain"]["events"]["last_event"]["logdesc"].startswith("Wireless station DNS process failed")
    assert {"step": "ap_radio", "reason": "dependency_missing",
            "detail": "the latest event has no radioid; radio and neighbor analysis depend on it"} in result["missing"]
    assert result["chain"]["radio"] is None and result["chain"]["neighbors"] is None


def test_events_are_ordered_by_utc_across_dst_with_epoch_fallback():
    lines = fixture("log_display_wireless").splitlines()
    disconnect = next(line for line in lines if line.startswith("12:"))
    error = next(line for line in lines if line.startswith("19:"))
    disconnect = disconnect.replace("2026-11-08 time=20:28:53", "2026-10-25 time=02:10:00")
    error = error.replace("2026-11-08 time=20:14:23", "2026-10-25 time=02:50:00").replace('tz="+0100"', 'tz="+0200"')
    result, _ = run(outputs(wifi_events="\n".join([disconnect, error])))
    assert result["chain"]["events"]["last_event"]["class"] == "client_disconnect"
    assert result["verdict"] == "incomplete"
    result, _ = run(outputs(wifi_events="\n".join([disconnect.replace('tz="+0100"', ''), error])))
    assert result["chain"]["events"]["last_event"]["time"].endswith("+00:00")
    # Without either device timezone or epoch, only that event is left out and counted.
    import re
    no_time_basis = re.sub(r"eventtime=\d+", "", disconnect.replace('tz="+0100"', ''))
    result, _ = run(outputs(wifi_events="\n".join([no_time_basis, error])))
    events = result["chain"]["events"]
    assert events["window"]["undated_records"] == 1
    assert events["last_event"]["time"] == "2026-10-25T02:50:00+02:00"
    assert {"step": "wifi_events", "reason": "unparsed"} not in result["missing"]


def test_busy_radio_notices_keep_unscoped_strong_neighbor_as_context_only():
    block = fixture("wtp_status").split("WTP: FAPEXAMPLE0000002")[1]
    radio = block.split("  Radio 2 ")[1].split("  Radio 3 ")[0]
    busy = radio.replace("oper-chutil-val  : 1 ", "oper-chutil-val  : 85 ").replace(
        "tx-retries       : 0%", "tx-retries       : 33%").replace("interfering-ap   : 0", "interfering-ap   : 9")
    text = fixture("wtp_status").replace(radio, busy)
    scan = fixture("scan").replace("00:00:5e:00:53:0e   48", "00:00:5e:00:53:0e  116").replace("-71    -95   100 EPs", "-48    -95   100 EPs", 1)
    result, _ = run(outputs(wifi_ap_status=text, wifi_neighbors=scan))
    assert ids(result) == ["F-WIFI-CLIENT-DISCONNECTED", "F-WIFI-RADIO-BUSY", "F-WIFI-RADIO-RETRIES",
                           "F-WIFI-RADIO-INTERFERENCE"]
    assert {f["severity"] for f in result["findings"]} == {"notice"}
    assert result["verdict"] == "incomplete"
    assert result["chain"]["neighbors"]["strongest_same_channel_dbm"] == -48
    assert "Helper threshold 70%" in result["findings"][1]["fact"]


def test_channel_change_between_event_and_now_is_only_a_hypothesis():
    text = fixture("wtp_status").replace("oper-chan        : 116", "oper-chan        : 100")
    result, _ = run(outputs(wifi_ap_status=text))
    assert "H-WIFI-CHANNEL-CHANGED" in [h["id"] for h in result["hypotheses"]]
    assert "F-WIFI-CHANNEL-CHANGED" not in ids(result)


@pytest.mark.parametrize("query,step", [
    ("wifi_events", "wifi_events"), ("wifi_ap_status", "wifi_ap_status"), ("wifi_vap_status", "wifi_vap_status"),
    ("wifi_rf_analysis", "wifi_rf_analysis"), ("wifi_neighbors", "wifi_neighbors"),
])
def test_a_refused_read_is_a_missing_step_and_never_a_verdict(query, step):
    result, _ = run(outputs(), refused={query: "permission_denied"})
    assert {"step": step, "reason": "permission_denied"} in result["missing"]
    assert result["verdict"] == "incomplete"
    assert any(m["step"] == "client_rssi" for m in result["missing"])


def test_unparsed_output_is_not_trusted():
    result, _ = run(outputs(wifi_ap_status=fixture("wtp_status") + "    surprise : 1\n"))
    assert {"step": "wifi_ap_status", "reason": "unparsed"} in result["missing"]
    assert result["chain"]["access_point"] is None and result["chain"]["radio"] is None
    assert "ap_radio" in steps(result)


def test_ap_or_vap_absent_from_the_listings_is_reported():
    only_first = fixture("wtp_status").split("WTP: FAPEXAMPLE0000002")[0]
    result, _ = run(outputs(wifi_ap_status=only_first))
    assert {"step": "ap_radio", "reason": "not_listed",
            "detail": "the selected access point is not in wtp-status"} in result["missing"]
    other_vap = fixture("vap_status").replace("ssid-17", "ssid-99")
    result, _ = run(outputs(wifi_vap_status=other_vap))
    assert "vap" in steps(result) and result["chain"]["vap"] is None


def test_identity_other_than_the_measured_model_is_refused():
    for status in ("Version: FortiGate-60F v7.6.8,build3744,260115 (GA.M)\n",
                   "Version: FortiGate-80F v8.0.2,build0252,260928 (GA.F)\n", "garbage"):
        with pytest.raises(triage_health.UnsupportedPlatform):
            run(outputs(system_status=status))


@pytest.mark.parametrize("mac,ip", [
    (None, None), (CLIENT, "192.0.2.19"), ("00:00:5E:00:53:37", None), ("00:00:5e:00:53", None), (None, "192.0.2.019"),
    (None, "192.0.2.19/24"), (None, "::1"), ("*", None), (CLIENT + "\nexecute reboot", None),
])
def test_exactly_one_canonical_client_selector_is_required(mac, ip):
    with pytest.raises(ValueError, match="invalid_argument"):
        run(outputs(), mac=mac, ip=ip)


def test_next_steps_use_only_tools_that_exist_and_verified_values():
    result, _ = run(outputs())
    assert [step["tool"] for step in result["next_steps"]] == ["ssh_read", "ssh_read", "locate_endpoint"]
    assert result["next_steps"][0]["arguments"]["parameters"] == {"wtp_id": AP2}
    assert result["next_steps"][2]["arguments"] == {"targets": [ALIAS], "endpoint": CLIENT}


def test_next_steps_carry_the_target_and_are_callable_as_they_are():
    result, _ = run(outputs())
    for step in result["next_steps"]:
        arguments = step["arguments"]
        assert arguments.get("target") == ALIAS or arguments.get("targets") == [ALIAS], step


def test_one_undated_event_is_counted_and_does_not_drop_the_step():
    undated = ('99: date=2026-11-08 time=20:50:00 type="event" subtype="wireless" level="notice" '
               'logdesc="Wireless client associated" stamac="%s" ssid="x"\n' % CLIENT)
    values = outputs()
    values["wifi_events"] = values["wifi_events"] + "\n" + undated
    result, _ = run(values)
    assert result["chain"]["events"]["window"]["undated_records"] == 1
    assert result["chain"]["events"]["window"]["client_records"] == 4
    assert "wifi_events" in result["checked"]
    assert {"step": "wifi_events", "reason": "unparsed"} not in result["missing"]
