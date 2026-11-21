"""G107: Ruckus Unleashed client, radio, AP and WLAN reads on real output of R610 on Ruckus Unleashed 200.15.6.212.27
(fixtures/ruckus_g107).

Parsers are exercised on the anonymised captures; engine reads go through a scripted PTY terminal that answers
the Unleashed login dialogue and then returns the captured output, so the real PTY body handling, redaction,
refusal detection and the `wifi` payload are what is tested.
"""

import dataclasses
import re
from pathlib import Path

import pytest

from conftest import LOGIN, PASSWORD, _target
import netops_helper.engine as engine
from netops_helper import proxy, wifi_parse
from netops_helper.read_policy import _validate_slot, render_read_query

FIXTURES = Path(__file__).parent / "fixtures" / "ruckus_g107"
AP_MAC = "00:00:5e:00:53:02"
CLIENT_MAC = "00:00:5e:00:53:04"
ALL = ("clients", "client_detail", "client_performance", "radio_performance_24", "radio_performance_5",
       "rogue_devices", "events", "access_points", "access_point", "access_point_by_name", "wlans", "wlan")


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def body(name):
    """The fixture as the Helper hands it to the parser: without the echoed command line."""
    return fixture(name).split("\n", 1)[1]


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    engine._WTP_SEEN.clear()
    engine._SSH_PAGE_CACHE.clear()
    yield
    engine._WTP_SEEN.clear()
    engine._SSH_PAGE_CACHE.clear()


def unleashed(monkeypatch, outputs, sent):
    """Scripted Unleashed PTY: login prompts, `enable`, then each command answered by the next capture."""
    script = iter(outputs)

    class Terminal:
        def __init__(self, *args, **options):
            self.buffer = [b"Welcome to the Ruckus Unleashed Network Command Line Interface\r\nPlease login: "]
            self.answered = 0

        def expect(self, patterns, timeout):
            return 0, self.buffer.pop(0)

        def discard(self, seen):
            pass

        def send(self, text):
            sent.append(text)
            self.answered += 1
            if self.answered == 1:
                self.buffer.append(b"Password: ")
            elif self.answered == 2:
                self.buffer.append(b"Login success\r\nruckus> ")
            elif self.answered == 3:
                self.buffer.append(b"enable\r\nruckus#")
            else:
                captured = fixture("show_sysinfo.out") if text == "show sysinfo" else next(script)
                answer = captured.replace("\n", "\r\n").encode()
                self.buffer.append(answer + b"\r\nruckus#")

        def close(self):
            pass

    monkeypatch.setattr(engine.core_session, "Session", Terminal)


def target(*queries, inventory=None):
    auth = _target("ruckus_unleashed", queries[0], legacy_ssh="rsa-sha1")
    return dataclasses.replace(auth, enabled_queries=tuple(queries), read_inventory=inventory or {})


def read(auth, query, parameters=None):
    return engine.ssh_read(auth, "ruckus_unleashed", query, parameters or {}, 0, 48_000)


# --- parsers on real output ---------------------------------------------------------------------

def test_client_list_normalises_every_client_and_counts_per_ap_and_wlan():
    parsed = wifi_parse.summarize_ruckus("clients", body("show_current_active_clients_all.out"))
    assert parsed["unparsed"] == [] and parsed["client_count"] == 13 == len(parsed["records"])
    first = parsed["records"][0]
    assert {key: first[key] for key in ("mac", "ip", "ap_mac", "bssid", "wlan", "vlan_id", "channel", "radio",
                                        "signal", "status", "connected_since")} == {
        "mac": CLIENT_MAC, "ip": "198.51.100.6", "ap_mac": AP_MAC, "bssid": "00:00:5e:00:53:05",
        "wlan": "ssid01", "vlan_id": 20, "channel": 11, "radio": "802.11gn", "signal": 67,
        "status": "Authorized", "connected_since": "2026-11-17T19:30:46"}
    assert parsed["clients_per_ap"] == {AP_MAC: 13}
    assert parsed["clients_per_wlan"] == {"ssid01": 6, "ssid02": 4, "ssid03": 3}
    assert all(record["mac"] and record["ap_mac"] for record in parsed["records"])


def test_one_client_adds_traffic_and_retry_drop_counters():
    parsed = wifi_parse.summarize_ruckus("client_detail", body("show_current_active_clients_mac_CLIENT.out"))
    assert parsed["unparsed"] == [] and len(parsed["records"]) == 1
    record = parsed["records"][0]
    assert (record["rx_packets"], record["rx_bytes"], record["tx_packets"], record["tx_bytes"],
            record["tx_retry_fail_drops"]) == (401, 44510, 312, 22580, 0)
    assert parsed["events"] == []


def test_absent_client_is_an_empty_listing_not_an_error():
    parsed = wifi_parse.summarize_ruckus("client_detail", body("client_mac_absent.out"))
    assert parsed["records"] == [] and parsed["unparsed"] == [] and parsed["client_count"] == 0


def test_truncated_client_output_reports_the_broken_line():
    text = body("show_current_active_clients_mac_CLIENT.out")
    cut = text[: text.index("401 pkts") + len("401 pk")]
    parsed = wifi_parse.summarize_ruckus("client_detail", cut)
    assert len(parsed["records"]) == 1 and parsed["records"][0]["rx_packets"] is None
    assert parsed["unparsed"] == [len(cut.split("\n"))]


@pytest.mark.parametrize("query, name", [("access_points", "show_ap_all.out"), ("access_point", "show_ap_mac_AP.out"),
                                         ("access_point_by_name", "show_ap_devname_NAME.out"),
                                         ("access_point", "ap_mac_uppercase.out")])
def test_access_point_radios_channels_width_and_ports(query, name):
    parsed = wifi_parse.summarize_ruckus(query, body(name))
    assert parsed["unparsed"] == [] and parsed["ap_count"] == 1
    ap = parsed["records"][0]
    assert (ap["mac"], ap["name"], ap["model"], ap["role"], ap["approved"], ap["ip"]) == (
        AP_MAC, "host01", "r610", "Master", True, "192.0.2.5")
    assert [(r["band"], r["channel"], r["width_mhz"], r["tx_power"], r["wlan_enabled"]) for r in ap["radios"]] == [
        ("5g", 56, 40, "Full", True), ("2.4g", 11, 20, "Full", True)]
    assert [(p["interface"], p["logical_link"], p["physical_link"]) for p in ap["lan_ports"]] == [
        ("eth0", "Up", "Up 1000Mbps full"), ("eth1", "Down", "Down")]


def test_wlan_table_ssid_vlan_band_and_service_state():
    parsed = wifi_parse.summarize_ruckus("wlans", body("show_wlan_all.out"))
    assert parsed["unparsed"] == [] and parsed["wlan_count"] == 3
    assert [(w["id"], w["name"], w["ssid"], w["vlan_id"], w["band"], w["service_enabled"], w["encryption"])
            for w in parsed["records"]] == [
        (1, "ssid03", "ssid03", 1, "5g", True, "wpa2"),
        (2, "ssid02", "ssid02", 30, "2.4g", False, "none"),
        (3, "ssid01", "ssid01", 20, "2.4g", True, "wpa2")]
    one = wifi_parse.summarize_ruckus("wlan", body("show_wlan_name_WLAN.out"))
    assert one["records"] == [parsed["records"][1]]


def test_records_never_carry_a_passphrase_even_if_printed():
    text = body("show_wlan_all.out").replace("      Algorithm = aes\n", "      Algorithm = aes\n      Passphrase = s3cr3t-psk\n", 1)
    parsed = wifi_parse.summarize_ruckus("wlans", text)
    assert "s3cr3t-psk" not in repr(parsed)


@pytest.mark.parametrize("query, name, expected", [
    ("radio_performance_24", "show_performance_ap_radio2_4_mac_AP.out",
     {"mac": AP_MAC, "radio": "b/g/n", "band": "2.4g", "estimated_capacity": 23870, "downlink": 0, "uplink": 0,
      "rf_pollution": 132, "authorized_clients": 10, "other_aps": 4, "counters_reported": True}),
    ("radio_performance_5", "show_performance_ap_radio5_mac_AP.out",
     {"mac": AP_MAC, "radio": "a/n", "band": "5g", "estimated_capacity": 256801, "downlink": 1568, "uplink": 70,
      "rf_pollution": 6, "authorized_clients": 3, "other_aps": 0, "counters_reported": True}),
    ("client_performance", "show_performance_station_mac_CLIENT.out",
     {"mac": CLIENT_MAC, "radio": None, "band": None, "estimated_capacity": 0, "downlink": 0, "uplink": 0,
      "counters_reported": True}),
])
def test_radio_and_station_performance(query, name, expected):
    parsed = wifi_parse.summarize_ruckus(query, body(name))
    assert parsed["unparsed"] == [] and parsed["records"] == [expected] and parsed["incomplete"] is False


@pytest.mark.parametrize("query, name, radio", [("radio_performance_24", "performance_radio24_header_only.out", "b/g/n"),
                                               ("radio_performance_5", "performance_radio5_header_only.out", "a/n")])
def test_header_only_radio_performance_is_incomplete_not_zero(query, name, radio):
    parsed = wifi_parse.summarize_ruckus(query, body(name))
    assert parsed["unparsed"] == [] and parsed["incomplete"] is True
    assert parsed["records"] == [{"mac": AP_MAC, "radio": radio, "band": "2.4g" if radio == "b/g/n" else "5g",
                                  "estimated_capacity": None, "downlink": None, "uplink": None, "rf_pollution": None,
                                  "authorized_clients": None, "other_aps": None, "counters_reported": False}]


def test_header_only_answer_through_the_engine_is_ok_but_marked_incomplete(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, [fixture("performance_radio5_header_only.out")], sent)
    result = read(target("radio_performance_5"), "radio_performance_5", {"ap_mac": AP_MAC})
    assert result["ok"] is True, result
    assert result["wifi"]["incomplete"] is True and result["wifi"]["records"][0]["downlink"] is None


def test_rogue_devices_and_events():
    rogues = wifi_parse.summarize_ruckus("rogue_devices", body("show_rogue_devices.out"))
    assert rogues["unparsed"] == [] and rogues["active_count"] == 8 == len(rogues["records"])
    assert rogues["records"][0] == {"list": "active", "mac": "00:00:5e:00:53:14", "channel": 1, "radio": "802.11g/n",
                                    "type": "AP", "encryption": "Encrypted", "ssid": "ssid04",
                                    "last_detected": "2026-11-12T20:40:03"}
    events = wifi_parse.summarize_ruckus("events", body("show_events.out"))
    assert events["unparsed"] == [] and len(events["records"]) == 5
    assert events["records"][0] == {"time": "2026-10-08T08:34:48", "severity": "High", "user": None,
                                    "message": "host-14"}


def test_every_g107_query_has_a_parser():
    later_queries = {"ping", "ethernet_info", "events_activities", "mesh_topology",
                     "l2_acls", "mgmt_acls", "l3_acls", "aaa_servers",
                     "dhcp_relays", "static_routes", "config_settings"}
    assert set(ALL) | later_queries == set(wifi_parse.RUCKUS_PARSERS)


# --- engine through the scripted PTY ----------------------------------------------------------------

def test_client_list_read_sends_only_the_enrolled_query_and_identity(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, [fixture("show_current_active_clients_all.out")], sent)
    result = read(target("clients", "system_info"), "clients")
    assert result["ok"] is True, result
    assert sent == [LOGIN, PASSWORD, "enable", "show current-active-clients all",
                    LOGIN, PASSWORD, "enable", "show sysinfo"]
    assert result["wifi"]["client_count"] == 13 and result["wifi"]["unparsed"] == []
    assert result["wifi"]["complete"] is True
    assert PASSWORD not in repr(result)


def test_client_detail_takes_a_lower_case_mac_literal(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, [fixture("show_current_active_clients_mac_CLIENT.out")], sent)
    result = read(target("client_detail", "system_info"), "client_detail", {"mac": CLIENT_MAC})
    assert result["ok"] is True, result
    assert sent[3::4] == ["show current-active-clients mac " + CLIENT_MAC, "show sysinfo"]
    assert result["wifi"]["records"][0]["rx_bytes"] == 44510
    for bad in ("00:00:5E:00:53:04", "00-00-5e-00-53-04", "00:00:5e:00:53:04;reboot", "all"):
        with pytest.raises(ValueError):
            render_read_query("ruckus_unleashed", "client_detail", {"mac": bad}, {})


def test_absent_object_is_a_refusal_with_a_plain_reason(wire, monkeypatch):
    for query, parameters, name in (
        ("access_point", {"ap_mac": "00:00:5e:00:53:01"}, "ap_mac_absent.out"),
        ("radio_performance_5", {"ap_mac": "00:00:5e:00:53:01"}, "performance_radio5_absent.out"),
        ("radio_performance_24", {"ap_mac": "00:00:5e:00:53:01"}, "performance_radio24_absent.out"),
        ("client_performance", {"mac": "00:00:5e:00:53:03"}, "performance_station_absent.out"),
    ):
        sent = []
        unleashed(monkeypatch, [fixture(name)], sent)
        result = read(target(query), query, parameters)
        assert result["ok"] is False, (query, result)
        assert result["error_code"] == "device_cli_error"
        assert result["error"] == "The device has no access point, WLAN or client with that MAC address or name"
        assert "wifi" not in result


def test_absent_client_reads_as_an_empty_ok_listing(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, [fixture("client_mac_absent.out")], sent)
    result = read(target("client_detail"), "client_detail", {"mac": "00:00:5e:00:53:03"})
    assert result["ok"] is True, result
    assert result["wifi"]["records"] == []


def test_ap_name_and_wlan_name_are_selectable_only_after_the_target_listed_them(wire, monkeypatch):
    auth = target("access_points", "access_point_by_name", "wlans", "wlan", "system_info")
    for query, parameters in (("access_point_by_name", {"wtp_id": "host01"}), ("wlan", {"wlan": "ssid02"})):
        with pytest.raises(Exception):
            read(auth, query, parameters)
    sent = []
    unleashed(monkeypatch, [fixture("show_ap_all.out"), fixture("show_wlan_all.out"),
                            fixture("show_ap_devname_NAME.out"), fixture("show_wlan_name_WLAN.out"),
                            fixture("wlan_name_absent.out")], sent)
    assert read(auth, "access_points")["ok"] is True
    assert read(auth, "wlans")["ok"] is True
    by_name = read(auth, "access_point_by_name", {"wtp_id": "host01"})
    assert by_name["ok"] is True and by_name["wifi"]["records"][0]["mac"] == AP_MAC
    wlan = read(auth, "wlan", {"wlan": "ssid02"})
    assert wlan["ok"] is True and wlan["wifi"]["records"][0]["vlan_id"] == 30
    assert sent.count("enable") == 8
    assert [line for line in sent if line.startswith("show ")] == [
        "show ap all", "show sysinfo", "show wlan all", "show sysinfo",
        "show ap devname host01", "show sysinfo", "show wlan name ssid02", "show sysinfo"]
    with pytest.raises(Exception):
        read(auth, "wlan", {"wlan": "ssid99"})
    # An enrolled name that the device does not know is a refusal, not a guess.
    enrolled = dataclasses.replace(auth, read_inventory={"wlan_names": ("NoSuchWlan",)})
    absent = read(enrolled, "wlan", {"wlan": "NoSuchWlan"})
    assert absent["ok"] is False and absent["error_code"] == "device_cli_error"


def test_wlan_name_and_ap_name_kinds_refuse_free_strings():
    for bad in ("all", "ALL", "two words", "a;b", "", "x" * 33, "-lead"):
        with pytest.raises(ValueError):
            _validate_slot(bad, "ruckus_wlan_name")
        assert not proxy._valid_typed_inventory_value(bad, "ruckus_wlan_name")
    assert _validate_slot("Guest-WLAN.2", "ruckus_wlan_name") == "Guest-WLAN.2"
    assert proxy._valid_typed_inventory_value("Guest-WLAN.2", "ruckus_wlan_name")


# --- 475-r2: review findings 1, 4 and 5, through the engine with the scripted PTY and real captures ---------------

# Made-up secrets (never device values); the words with spaces check that the whole value is hidden, not a first word.
_FAKE_SECRETS = {
    "Key": "UKAZKOVA-HODNOTA-KLIC",
    "RADIUS Key": "SMYSLENY radiusKLIC mezerami",
    "Passphrase": "TAJNA fraze BEZUVO uvozovek",
    "PSK": "psk-ALFA bravo-CHARLIE",
    "SAE-Passphrase": "SAEHODNOTA",
    "Secret": "AAATAJ tajemstvi DELTA",
}
_FAKE_WORDS = sorted({word for value in _FAKE_SECRETS.values() for word in value.split()})


def _with_fake_secrets(text):
    """Secret lines after every `Encryption = …` of a WLAN, as Unleashed prints them: `Label = value`, no quotes."""
    lines = "".join(f"      {label} = {value}\n\n" for label, value in _FAKE_SECRETS.items())
    lines += "      Dynamic PSK = Disabled\n\n"
    out = []
    for line in text.split("\n"):
        out.append(line)
        if line.strip().startswith("Encryption = "):
            out.append("\n" + lines.rstrip("\n"))
    return "\n".join(out)


def _assert_no_fake_secret(where):
    blob = repr(where)
    leaked = [word for word in _FAKE_WORDS if word in blob]
    assert leaked == [], leaked


@pytest.mark.parametrize("query, name, parameters", [
    ("wlan", "show_wlan_name_WLAN.out", {"wlan": "ssid02"}),
    ("wlans", "show_wlan_all.out", {}),
])
def test_475r2_wlan_secret_lines_are_redacted_whole_in_the_response_and_page_cache(wire, monkeypatch, query, name,
                                                                                   parameters):
    captured = _with_fake_secrets(fixture(name))
    assert all(word in captured and word not in fixture(name) and len(word) >= 5 for word in _FAKE_WORDS)
    sent = []
    unleashed(monkeypatch, [captured], sent)
    auth = target(query, inventory={"wlan_names": ("ssid02",)} if query == "wlan" else None)
    pages = [engine.ssh_read(auth, "ruckus_unleashed", query, parameters, 0, 1_000)]
    assert pages[0]["ok"] is True, pages[0]
    assert pages[0]["next_offset"] is not None  # paged: the rest is served from the page cache
    _assert_no_fake_secret(engine._SSH_PAGE_CACHE)
    while pages[-1]["next_offset"] is not None:
        pages.append(engine.ssh_read(auth, "ruckus_unleashed", query, parameters, pages[-1]["next_offset"], 1_000,
                                     pages[0]["content_sha256"]))
        assert pages[-1]["ok"] is True and pages[-1]["pagination_source"] == "cached", pages[-1]
    _assert_no_fake_secret(pages)
    text = "".join(page["untrusted_device_output"] for page in pages)
    # Every redacted line holds only its label and markers (later general layers may rewrite `Secret = <REDACTED>`,
    # e.g. to `[REDACTED]`): no fragment of a value with spaces survives next to the marker.
    marked = [line for line in text.split("\n") if "REDACTED" in line]
    labels = "|".join(re.escape(label) for label in sorted(_FAKE_SECRETS, key=len, reverse=True))
    rest = [line for line in marked
            if re.sub(rf"<REDACTED>|\[REDACTED\]|{labels}|[=:\s]", "", line)]
    assert rest == [] and len(marked) == len(_FAKE_SECRETS) * captured.count("Encryption = ")
    assert "Dynamic PSK = Disabled" in text
    assert pages[0]["wifi"]["records"] and pages[0]["wifi"]["unparsed"] == []


def test_475r2_ruckus_secret_redaction_keeps_markers_and_dynamic_psk_state():
    from netops_helper.sanitize import redact_ruckus_secrets

    text = ("  Key = a b c\n  RADIUS Key= x y\n  Secret:  s t \n  Passphrase = <REDACTED>\n  Dynamic PSK = Enabled\n"
            "  Key Index = \n  NAME = keyless\n  SSID = psk net\n")
    assert redact_ruckus_secrets(text) == (
        "  Key = <REDACTED>\n  RADIUS Key= <REDACTED>\n  Secret:  <REDACTED>\n  Passphrase = <REDACTED>\n"
        "  Dynamic PSK = Enabled\n  Key Index = \n  NAME = keyless\n  SSID = psk net\n")


def test_475r2_paged_wlan_inventory_is_complete_on_every_page(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, [fixture("show_wlan_all.out")], sent)
    auth = target("wlans")
    pages = [engine.ssh_read(auth, "ruckus_unleashed", "wlans", {}, 0, 1_000)]
    while pages[-1]["next_offset"] is not None:
        pages.append(engine.ssh_read(auth, "ruckus_unleashed", "wlans", {}, pages[-1]["next_offset"], 1_000,
                                     pages[0]["content_sha256"]))
    assert len(pages) > 2
    assert [page["wifi"]["complete"] for page in pages] == [True] * len(pages)
    assert {page["wifi"]["wlan_count"] for page in pages} == {3}
    assert not any(page["wifi"].get("incomplete") for page in pages)


def test_475r2_header_only_radio_answer_is_not_complete(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, [fixture("performance_radio5_header_only.out")], sent)
    result = read(target("radio_performance_5"), "radio_performance_5", {"ap_mac": AP_MAC})
    assert result["ok"] is True and result["complete"] is True and result["next_offset"] is None  # one text page
    assert result["wifi"]["incomplete"] is True and result["wifi"]["complete"] is False


def _event_message(text):
    """show_events.out with the message of the first event (line 13) replaced, indentation kept."""
    lines = fixture("show_events.out").split("\n")
    assert lines[12] == "    host-14"
    lines[12] = "    " + text
    return "\n".join(lines)


@pytest.mark.parametrize("message, expected", [
    (["Stav stanice = odpojena"], "Stav stanice = odpojena"),
    (["Klient roamoval na AP:", "Stav stanice = odpojena"], "Klient roamoval na AP: Stav stanice = odpojena"),
])
def test_475r2_event_message_with_equals_or_colon_is_kept(wire, monkeypatch, message, expected):
    sent = []
    unleashed(monkeypatch, [_event_message("\n\n    ".join(message))], sent)
    result = read(target("events"), "events")
    assert result["ok"] is True, result
    events = result["wifi"]
    assert events["unparsed_count"] == 0 and events["complete"] is True
    assert events["records"][0] == {"time": "2026-10-08T08:34:48", "severity": "High", "user": None,
                                    "message": expected}
    assert [record["message"] for record in events["records"][1:]] == ["host-15", "host-16", "host-17", "host-18"]


def test_475r2_client_detail_event_message_with_equals_or_colon_is_kept(wire, monkeypatch):
    history = ("\n  Activity:\n\n    Date/Time= 2026/10/08 08:34:48\n\n    Severity= Low\n\n    User= \n\n"
               "    Stav stanice = odpojena\n\n    Klient roamoval na AP:\n\n    Duvod= roaming\n\n"
               "  Activity:\n\n    Date/Time= spatny cas\n\n    Severity= Low\n\n    User= \n\n    host-20\n")
    sent = []
    unleashed(monkeypatch, [fixture("show_current_active_clients_mac_CLIENT.out") + history], sent)
    result = read(target("client_detail"), "client_detail", {"mac": CLIENT_MAC})
    assert result["ok"] is True, result
    wifi = result["wifi"]
    assert wifi["records"][0]["rx_bytes"] == 44510
    assert [event["message"] for event in wifi["events"]] == [
        "Stav stanice = odpojena Klient roamoval na AP: Duvod= roaming", "host-20"]
    assert wifi["events"][0]["severity"] == "Low" and wifi["events"][1]["time"] is None
    assert wifi["unparsed_count"] == 1 and wifi["complete"] is False  # the unreadable Date/Time is reported


# --- 475-r3: review 475-r2-rv findings 1 and 2, through the engine with the scripted PTY and real captures ----------

# Made-up values (never device values) on secret lines whose label the device splits by terminal controls.
_CONTROL_SECRETS = (
    ("K\x1b[1me\x1b[0my", "ANSIKLIC hodnota JEDNA"),
    ("RADIUS\x1b[0m Key", "ANSIRADIUS hodnota DVA"),
    ("Guest Fr\x1b[7miendly\x1b[27m Key", "ANSIHOST hodnota TRI"),
    ("Kez\by", "BACKSPACEKLIC hodnota CTYRI"),
    ("P\x07SK", "ZVONEKPSK hodnota PET"),
    ("\x1b[2KKey", "MAZANIRADKU hodnota SEST"),
)
_CONTROL_WORDS = sorted({word for _, value in _CONTROL_SECRETS for word in value.split() if word != "hodnota"})


@pytest.mark.parametrize("query, name, parameters", [
    ("wlan", "show_wlan_name_WLAN.out", {"wlan": "ssid02"}),
    ("wlans", "show_wlan_all.out", {}),
])
def test_475r3_secret_label_with_terminal_controls_is_redacted_in_the_response_and_page_cache(
        wire, monkeypatch, query, name, parameters):
    lines = "".join(f"      {label} = {value}\n\n" for label, value in _CONTROL_SECRETS)
    captured = fixture(name).replace("      Encryption = ", lines + "      Encryption = ")
    assert all(word in captured and word not in fixture(name) for word in _CONTROL_WORDS)
    sent = []
    unleashed(monkeypatch, [captured], sent)
    auth = target(query, inventory={"wlan_names": ("ssid02",)} if query == "wlan" else None)
    pages = [engine.ssh_read(auth, "ruckus_unleashed", query, parameters, 0, 1_000)]
    assert pages[0]["ok"] is True, pages[0]
    assert pages[0]["next_offset"] is not None  # paged: the rest is served from the page cache
    cached = repr(engine._SSH_PAGE_CACHE)
    assert [word for word in _CONTROL_WORDS if word in cached] == []
    while pages[-1]["next_offset"] is not None:
        pages.append(engine.ssh_read(auth, "ruckus_unleashed", query, parameters, pages[-1]["next_offset"], 1_000,
                                     pages[0]["content_sha256"]))
        assert pages[-1]["ok"] is True and pages[-1]["pagination_source"] == "cached", pages[-1]
    blob = repr(pages)
    assert [word for word in _CONTROL_WORDS if word in blob] == []
    text = "".join(page["untrusted_device_output"] for page in pages)
    assert "\x1b" not in text and "\x07" not in text
    for label in ("Key", "RADIUS Key", "Guest Friendly Key", "PSK"):
        assert re.search(rf"(?m)^ *{label} = (?:<REDACTED>|\[REDACTED\])$", text), label
    assert pages[0]["wifi"]["records"]


def _golden_wlan_all(guest_friendly_key=None):
    """tests/v1/fixtures/ruckus_show_wlan_all.golden.txt (real R610 layout) as the Unleashed PTY answers `show wlan all`."""
    golden = (Path(__file__).resolve().parents[3] / "tests" / "v1" / "fixtures"
              / "ruckus_show_wlan_all.golden.txt").read_text(encoding="utf-8")
    lines = golden.split("\n")
    assert lines[:2] == ["enable", "ruckus# show wlan all"] and lines[100] == "      Guest Friendly Key = Disabled"
    if guest_friendly_key is not None:
        lines[100] = "      Guest Friendly Key = " + guest_friendly_key
    text = "\n".join(["show wlan all"] + lines[2:]).rstrip()
    assert text.endswith("ruckus#")
    return text[: -len("ruckus#")].rstrip()


def _read_golden(wire, monkeypatch, text):
    sent = []
    unleashed(monkeypatch, [text], sent)
    result = read(target("wlans"), "wlans")
    assert result["ok"] is True and result["next_offset"] is None, result
    return result


@pytest.mark.parametrize("state", ["Disabled", "Enabled"])
def test_475r3_guest_friendly_key_state_is_kept_in_the_wlan_inventory(wire, monkeypatch, state):
    result = _read_golden(wire, monkeypatch, _golden_wlan_all(None if state == "Disabled" else state))
    text = result["untrusted_device_output"]
    assert f"      Guest Friendly Key = {state}\n" in text
    assert text.count("      Dynamic PSK = Disabled\n") == 2
    assert "netops-k01-psk-" not in repr(result)  # the passphrases of the same capture stay hidden


def test_475r3_guest_friendly_key_value_is_redacted_in_the_wlan_inventory(wire, monkeypatch):
    result = _read_golden(wire, monkeypatch, _golden_wlan_all("HOSTOVSKY smysleny KLIC"))
    blob = repr(result)
    assert not [word for word in ("HOSTOVSKY", "smysleny", "KLIC") if word in blob]
    assert re.search(r"(?m)^      Guest Friendly Key = (?:<REDACTED>|\[REDACTED\])$", result["untrusted_device_output"])
    assert "netops-k01-psk-" not in blob


def test_475r3_ruckus_state_lines_unit():
    from netops_helper.sanitize import redact_ruckus_secrets

    text = ("  Guest Friendly Key = Disabled\n  Guest Friendly Key = enabled\n  Guest Friendly Key = Disabled now\n"
            "  K\x1b[0mey = a b\n")
    assert redact_ruckus_secrets(text) == (
        "  Guest Friendly Key = Disabled\n  Guest Friendly Key = enabled\n  Guest Friendly Key = <REDACTED>\n"
        "  Key = <REDACTED>\n")


@pytest.mark.parametrize("query", ["events", "client_detail"])
@pytest.mark.parametrize("field, original, damaged", [
    ("time", "Date/Time= 2026/10/08 08:34:48", "Date/Time: 2026/10/08 08:34:48"),
    ("time", "Date/Time= 2026/10/08 08:34:48", "Date/Time 2026/10/08 08:34:48"),
    ("severity", "Severity= High", "Severity High"),
    ("user", "User= ", "User sample-netops-user"),
])
def test_damaged_event_header_preserves_the_message_and_remaining_fields(wire, monkeypatch, query, field,
                                                                        original, damaged):
    captured = fixture("show_events.out")
    if query == "client_detail":
        captured = (fixture("show_current_active_clients_mac_CLIENT.out")
                    + captured.split("Last 300 Events/Activities:", 1)[1])
    captured = captured.replace(original, damaged, 1)
    unleashed(monkeypatch, [captured], [])
    parameters = {"mac": CLIENT_MAC} if query == "client_detail" else None
    wifi = read(target(query), query, parameters)["wifi"]
    assert not wifi["complete"] and wifi["unparsed_count"] == 1
    rows = wifi["records"] if query == "events" else wifi["events"]
    expected = {"time": "2026-10-08T08:34:48", "severity": "High", "user": None, "message": "host-14"}
    expected[field] = None
    assert rows[0] == expected


@pytest.mark.parametrize("query", ["events", "client_detail"])
def test_event_message_with_header_label_after_valid_header(wire, monkeypatch, query):
    message = "User: odpojen klient"
    captured = _event_message(message)
    if query == "client_detail":
        captured = (fixture("show_current_active_clients_mac_CLIENT.out")
                    + captured.split("Last 300 Events/Activities:", 1)[1])
    unleashed(monkeypatch, [captured], [])
    parameters = {"mac": CLIENT_MAC} if query == "client_detail" else None
    wifi = read(target(query), query, parameters)["wifi"]
    assert wifi["complete"] and wifi["unparsed_count"] == 0
    rows = wifi["records"] if query == "events" else wifi["events"]
    assert rows[0] == {"time": "2026-10-08T08:34:48", "severity": "High", "user": None, "message": message}


@pytest.mark.parametrize("state", ["Disabled", "Enabled"])
@pytest.mark.parametrize("suffix", ["\x1b[0m", "\x1b[K", "\x1b[0m \x1b[?25h\x1b[2K", "\x1b]0;title\x07", "\x9bK"],
                         ids=["sgr", "erase", "mixed-csi", "osc", "c1-csi"])
def test_guest_friendly_key_state_before_ansi_controls(wire, monkeypatch, state, suffix):
    result = _read_golden(wire, monkeypatch, _golden_wlan_all(state + suffix))
    assert re.search(rf"(?m)^      Guest Friendly Key = {state}[ \t]*$", result["untrusted_device_output"])


@pytest.mark.parametrize("value", ["Enabled\x1b[K sample-guest-material", "Dis\x1b[Kabled", "Enabled sample\x1b[K"])
def test_guest_friendly_key_with_ansi_and_non_state_value_is_redacted(wire, monkeypatch, value):
    result = _read_golden(wire, monkeypatch, _golden_wlan_all(value))
    assert "      Guest Friendly Key = <REDACTED>\n" in result["untrusted_device_output"]
