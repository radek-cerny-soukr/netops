"""Wi-Fi parsers over the output measured on FortiGate-80F 8.0.2 build0251 with a read-only account."""

from pathlib import Path

import pytest

from netops_helper import wifi_parse as wp

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return (FIXTURES / ("fortios_80f_802_wifi_" + name + ".txt")).read_text(encoding="utf-8")


MEASURED = [
    ("wifi_ap_status", "wtp_status", 2),
    ("wifi_vap_status", "vap_status", 1),
    ("wifi_neighbors", "scan", 32),
    ("wifi_controller_status", "status", 1),
    ("wifi_controller_statistics", "statistics", 1),
    ("wifi_rf_analysis", "rf_analysis_one", 1),
    ("wifi_rf_analysis", "rf_analysis_controller", 3),
    ("wifi_events", "log_display_wireless", 20),
]


@pytest.mark.parametrize("query,name,count", MEASURED)
def test_measured_output_parses_completely(query, name, count):
    result = wp.summarize(query, fixture(name))
    assert result["unparsed"] == [] and result["unparsed_count"] == 0
    assert len(result["records"]) == count


def test_every_wifi_query_has_a_parser_and_a_measured_fixture():
    assert set(wp.PARSERS) == {query for query, _, _ in MEASURED}


def test_access_points_and_radios_are_normalised():
    first, second = wp.parse_wtp_status(fixture("wtp_status"))["records"]
    assert (first["serial"], first["ip"], first["state"], first["version"]) == (
        "FAPEXAMPLE0000001", "192.0.2.10", "Connected", "FP231K-v8.0.0-build0033")
    assert first["join_time"] is None
    assert "timezone" in first["join_time_note"]
    assert first["lldp"]["port_id"] == "port3" and first["lldp"]["system_name"] == "SWEXAMPLE00003"
    assert [(r["radio"], r["exists"], r["channel"]) for r in first["radios"]] == [
        (1, True, 1), (2, True, 124), (3, True, 0), (4, False, None), (5, False, None)]
    radio = first["radios"][0]
    assert (radio["client_count"], radio["chutil_percent"], radio["tx_power_dbm"], radio["tx_power_max_dbm"]) == (1, 4, 20, 20)
    assert (radio["rogue_ap"], radio["rogue_infra_ap"], radio["interfering_ap"]) == (12, 1, 4)
    assert radio["antenna_rssi"] == [7, 6] and radio["tx_retries_percent"] == 0
    assert radio["width_mhz"] is None  # wtp-status does not report the channel width
    assert first["radios"][2]["antenna_rssi"] is None
    assert second["serial"] == "FAPEXAMPLE0000002" and second["radios"][3]["mode"] == "Virtual Lan AP"
    assert second["radios"][1]["channel"] == 116


def test_vap_controller_and_scan_records():
    vap = wp.parse_vap_status(fixture("vap_status"))["records"][0]
    assert (vap["name"], vap["ssid"], vap["state"], vap["clients_online"], vap["clients_offline"]) == (
        "ssid-17", "ssid-17", "up", 2, 0)
    assert vap["local_switching"] is True and vap["local_bridging"] is False
    status = wp.parse_controller_status(fixture("status"))["records"][0]
    assert (status["wtp_active"], status["wtp_down"], status["clients_online"]) == (2, 0, 2)
    assert len(status["client_peak_hour"]) == 24 and status["client_peak_quarter"][0] == {"2.4G": 1, "5G": 1, "6G": 0, "all": 2}
    statistics = wp.parse_controller_statistics(fixture("statistics"))["records"][0]
    assert (statistics["wtp_sessions"], statistics["rogue_aps"], statistics["rogue_clients"]) == (2, 53, 0)
    scan = wp.parse_scan(fixture("scan"))["records"]
    assert scan[0] == {
        "ssid": "ssid-01", "bssid": "00:00:5e:00:53:0e", "channel": 48, "rate_mbps": 866, "signal_dbm": -71,
        "noise_dbm": -95, "beacon_interval": 100, "capabilities": "EPs", "active": True, "live_s": 8565,
        "age_s": 384, "wired": "?", "flags": "UNNN", "classification": "U", "vf": 0,
        "security": ["WME", "ATH", "VEN", "WPA", "CCMP", "TKIP", "RSN", "VEN", "VEN"]}
    assert sum(1 for item in scan if item["ssid"] is None) == 15  # hidden SSIDs have an empty column
    assert [item["active"] for item in scan].count(False) == 9


def test_rf_analysis_rows():
    table = wp.parse_rf_analysis(fixture("rf_analysis_one"))["records"][0]
    assert table["wtp"] == "FAPEXAMPLE0000001" and len(table["channels"]) == 24
    row = next(item for item in table["channels"] if item["channel"] == 104)
    assert row == {"channel": 104, "rssi_total": 1, "rf_score": 10, "overlap_ap": 1, "interfere_ap": 1,
                   "chan_utilization_percent": 10}


def test_rf_analysis_controller_block_is_read_as_controller_rows():
    # measured on FortiGate-80F 8.0.2 build0251 with two access points: the last block is `Controller: <id>` with the
    # two columns `channel rssi_total`
    result = wp.parse_rf_analysis(fixture("rf_analysis_controller"))
    assert [(item["scope"], item["wtp"]) for item in result["records"]] == [
        ("wtp", "FAPEXAMPLE0000001"), ("wtp", "FAPEXAMPLE0000002"), ("controller", None)]
    controller = result["records"][2]
    assert controller["controller"] == "FGTEXAMPLE0000001-0" and "channels" not in controller
    assert len(controller["controller_rows"]) == 26
    assert controller["controller_rows"][0] == {"channel": 1, "rssi_total": 77}
    assert controller["controller_rows"][-1] == {"channel": 165, "rssi_total": 33}
    assert result["unparsed"] == [] and result["unparsed_count"] == 0


@pytest.mark.parametrize("extra", ["     1 x\n", "     channel    rssi-total   rf-score\n     1   2\n", "     1  2  3\n"])
def test_rf_analysis_controller_block_with_another_shape_is_reported(extra):
    text = "Controller: FGTEXAMPLE0000001-0\n     channel    rssi_total  \n          1      77\n" + extra
    result = wp.parse_rf_analysis(text)
    assert result["records"][0]["controller_rows"][0] == {"channel": 1, "rssi_total": 77}
    assert result["unparsed_count"] >= 1


def test_events_are_normalised_and_classified():
    result = wp.parse_events(fixture("log_display_wireless"))
    assert (result["found"], result["returned"]) == (211, 20)
    by_index = {item["index"]: item for item in result["records"]}
    disassoc = by_index[12]
    assert disassoc["time"] == "2026-11-08T20:28:53+01:00" and disassoc["class"] == "client_disconnect"
    assert (disassoc["client_mac"], disassoc["ap"], disassoc["radio"], disassoc["channel"], disassoc["vap"]) == (
        "00:00:5e:00:53:37", "FAPEXAMPLE0000002", 2, 116, "ssid-17")
    assert (disassoc["signal_dbm"], disassoc["snr"], disassoc["reason"]) == (-33, 63, "Reserved 0")
    assert by_index[14]["client_ip"] == "192.0.2.24" and by_index[14]["signal_dbm"] == 0
    assert by_index[19]["class"] == "client_error" and by_index[19]["level"] == "warning"
    rogue = by_index[16]
    assert rogue["class"] == "rogue_ap" and rogue["client_mac"] is None and rogue["bssid"] == "00:00:5e:00:53:28"
    assert [item["class"] for item in result["records"]].count("rogue_ap") == 16


@pytest.mark.parametrize("logdesc,expected", [
    ("Wireless client disassociated", "client_disconnect"),
    ("Wireless client disconnected by WTP", "client_disconnect"),
    ("Wireless client deauthenticated", "client_disconnect"),
    ("Wireless client associated", "client_connect"),
    ("Wireless client authenticated", "client_connect"),
    ("Wireless client authentication failed", "client_error"),
    ("Wireless station DNS process failed with no server response", "client_error"),
    ("Rogue AP off air", "rogue_ap"),
    ("Wireless controller reboot", "other"),
])
def test_logdesc_classes(logdesc, expected):
    assert wp.classify_logdesc(logdesc) == expected


def test_unrecognised_lines_are_reported_not_guessed():
    text = fixture("wtp_status").replace("    tx-retries       : 0%", "    tx-retries       : lots", 1)
    result = wp.parse_wtp_status(text)
    assert result["unparsed"] == [next(n for n, line in enumerate(text.split("\n"), 1) if "lots" in line)]
    text = fixture("wtp_status") + "    surprise         : 1\n"
    assert wp.parse_wtp_status(text)["unparsed_count"] == 1
    assert wp.parse_scan(fixture("scan") + "garbage line\n")["unparsed_count"] == 1
    assert wp.parse_scan("")["unparsed_count"] == 1  # no table header at all
    assert wp.parse_events(fixture("log_display_wireless") + "\nsomething else\n")["unparsed_count"] == 1
    broken = fixture("log_display_wireless").replace('type="event"', 'type=event extra "', 1)
    assert wp.parse_events(broken)["unparsed_count"] == 1
    assert wp.parse_vap_status("WLAN: a\n    ssid : x\n    downup_oper : up\n    bogus : 1\n")["unparsed"] == [4]


def test_event_text_cannot_inject_fields():
    line = ('1: date=2026-11-08 time=20:28:53 tz="+0100" type="event" subtype="wireless" logdesc="Wireless client disassociated" '
            'stamac="00:00:5e:00:53:37" msg="x\\" stamac=\\"00:00:5e:00:53:99\\" ap=\\"EVIL\\""')
    record = wp.parse_events(line)["records"][0]
    assert record["client_mac"] == "00:00:5e:00:53:37" and record["ap"] is None


def test_mac_filter_keeps_only_matching_records_and_unrecognised_text():
    text = fixture("log_display_wireless")
    kept, info = wp.filter_events_by_mac(text, "00:00:5e:00:53:37")
    assert info == {"mac_literal": "00:00:5e:00:53:37", "scanned_lines": 20, "matched": 4}
    result = wp.parse_events(kept)
    assert [item["index"] for item in result["records"]] == [12, 13, 14, 19]
    assert (result["found"], result["returned"]) == (211, 20)
    assert result["unparsed_count"] == 0
    by_bssid, info = wp.filter_events_by_mac(text, "00:00:5e:00:53:28")
    assert info["matched"] == 2 and [r["index"] for r in wp.parse_events(by_bssid)["records"]] == [8, 16]
    none, info = wp.filter_events_by_mac(text, "00:00:5e:00:53:aa")
    assert info["matched"] == 0 and wp.parse_events(none)["records"] == []
    odd, _ = wp.filter_events_by_mac(text + "\nunexpected\n", "00:00:5e:00:53:aa")
    assert wp.parse_events(odd)["unparsed_count"] == 1


def test_mac_filter_ignores_a_mac_that_only_appears_in_free_text():
    line = ('1: date=2026-11-08 time=20:28:53 tz="+0100" type="event" subtype="wireless" logdesc="x client" '
            'stamac="00:00:5e:00:53:01" msg="peer 00:00:5e:00:53:37 mentioned"')
    assert wp.filter_events_by_mac(line, "00:00:5e:00:53:37")[1]["matched"] == 0


def test_event_without_timezone_uses_epoch_or_is_unparsed():
    from datetime import datetime
    assert datetime.fromisoformat(wp._event_time({"date": "2026-11-08", "time": "19:00:45",
                                                "eventtime": "1794160845000000000"})).utcoffset() is not None
    with pytest.raises(ValueError, match="offset"):
        wp._event_time({"date": "2026-11-08", "time": "19:00:45"})


def test_undated_event_is_left_out_and_counted_without_failing_the_others():
    text = fixture("log_display_wireless")
    undated = '99: date=2026-11-08 time=20:50:00 type="event" subtype="wireless" logdesc="Wireless client associated"'
    base = wp.parse_events(text)
    mixed = wp.parse_events(text + "\n" + undated + "\n")
    assert base["undated"] == 0
    assert mixed["undated"] == 1
    assert mixed["unparsed_count"] == 0
    assert len(mixed["records"]) == len(base["records"])
    broken = wp.parse_events(text + "\n99: date=2026-11-08 time=bad type=\"event\" subtype=\"wireless\"\n")
    assert broken["unparsed_count"] == 1 and broken["undated"] == 0


def test_split_matches_previous_parser_on_all_fixtures(monkeypatch):
    import re

    def previous(line):
        found = re.fullmatch(r"( *)([^:]*?) *:(?: (.*)|(.*))", line)
        if found is None or not found[2]:
            return None
        return len(found[1]), found[2], (found[3] if found[3] is not None else found[4]).strip()

    for path in FIXTURES.rglob('*.txt'):
        for line in wp._lines(path.read_text()):
            assert wp._split(line) == previous(line), (path, line)
    for query, name, _ in MEASURED:
        current = wp.summarize(query, fixture(name))
        with monkeypatch.context() as patch:
            patch.setattr(wp, '_split', previous)
            assert wp.summarize(query, fixture(name)) == current


def test_split_colons_spaces_and_tabs():
    for line, expected in [
        ('    key : value: rest ', (4, 'key', 'value: rest')),
        (' key\t :\tvalue', (1, 'key\t', 'value')),
        (' key:', (1, 'key', '')),
        ('     : value', None), ('no colon', None),
    ]:
        assert wp._split(line) == expected
