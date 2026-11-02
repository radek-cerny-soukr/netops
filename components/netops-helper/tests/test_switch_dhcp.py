from dataclasses import replace
from pathlib import Path
import json

from conftest import FORTIOS_STATUS, PASSWORD, _target
import netops_helper.engine as engine
from netops_helper.query_catalog.fortinet import QUERIES
from netops_helper.switch_dhcp import DHCP_BINDINGS_QUERY, summarize

A = "S224EPTF00000001"
HEADER = ("Flags    MAC Address    VLAN      Client IP        Lease Time(D:H:M:S)      Expiry Time(D:H:M:S)"
          "        Interface        Host Name    Domain Name    Vendor         Server IP     ")
SERVER_HEADER = ("      mac        vlan          ip            interface          status           svr-state"
                 "          last-seen-time             expiry-time         OFFER/ACK/NAK/OTHER")
LEGEND = "Flags: S (Static), A (ARP Monitor), D (DHCP Monitor)"
ROW_802 = ("       00:00:5E:00:53:01  52      192.0.2.10           0:0:15:0                 0:0:13:20"
           "               port18          host-a                                  192.0.2.1    ")
ROW_768 = ("       00:00:5e:00:53:02   1       198.51.100.2            7:0:0:0                  6:23:51:43"
           "               port3        FortiAP-23JK              FortiAP-FP23JK     198.51.100.1    ")
SERVER_ROW = ("00:00:5e:00:53:fe  52      192.0.2.1     FGT80F0000000001       trusted          disabled"
              "         2026-11-01 09:41:24       2026-11-02 09:41:24        1/1/0/0      ")


def status(rows=(ROW_802,), client6=(), end=True, newline="\n"):
    lines = ["Vdom: root", "", f"{A}:", "", "Client db: ", "", HEADER, *rows, "", "Server db: ", "",
             SERVER_HEADER, SERVER_ROW, "", "Client6 db: ", *client6, "", "Server6 db: ", ""]
    if end:
        lines.append(LEGEND)
    return newline.join(lines) + newline


def _all(text):
    return summarize(text, 0, len(text.encode("utf-8")))


def test_802_row_gives_mac_ip_vlan_port_and_server():
    result = _all(status())
    assert result == {
        "state": "ok", "total_bindings": 1, "unreadable_rows": 0, "ipv6_rows_present": False,
        "bindings": [{"flags": "", "mac": "00:00:5e:00:53:01", "vlan": 52, "ip": "192.0.2.10",
                      "lease": "0:0:15:0", "expiry": "0:0:13:20", "port": "port18", "server_ip": "192.0.2.1"}],
    }


def test_768_crlf_row_with_hostname_and_vendor_is_read():
    result = _all(status(rows=(ROW_768, ROW_802), newline="\r\n"))
    assert result["state"] == "ok" and result["total_bindings"] == 2
    first = result["bindings"][0]
    assert (first["mac"], first["vlan"], first["ip"], first["port"], first["server_ip"]) == (
        "00:00:5e:00:53:02", 1, "198.51.100.2", "port3", "198.51.100.1")
    assert "FortiAP" not in json.dumps(result)


def test_flags_column_is_kept():
    row = "D      00:00:5e:00:53:03  52      192.0.2.11           0:0:15:0                 0:0:14:00               port7    192.0.2.1"
    result = _all(status(rows=(row,)))
    assert result["state"] == "ok" and result["bindings"][0]["flags"] == "D"
    assert result["bindings"][0]["port"] == "port7"


def test_empty_client_table_is_empty_not_ok():
    result = _all(status(rows=()))
    assert result["state"] == "empty" and result["bindings"] == [] and result["total_bindings"] == 0


def test_switch_without_bindings_prints_no_header_and_is_empty():
    text = (f"Vdom: root\n\n{A}:\n\r\nClient db: \r\n\r\nServer db: \r\n\r\nClient6 db: \r\n\r\n"
            f"Server6 db: \r\n\n{LEGEND}\n\r\n\n\n")
    result = _all(text)
    assert result == {"state": "empty", "total_bindings": 0, "unreadable_rows": 0,
                      "ipv6_rows_present": False, "bindings": []}
    assert _all(text.replace(LEGEND, ""))["state"] == "incomplete"


def test_cut_or_foreign_answer_is_incomplete():
    assert _all(status(end=False))["state"] == "incomplete"
    assert _all("")["state"] == "incomplete"
    assert _all("Vdom: root\n\nsnoop-enabled-vlans : 52\n" + LEGEND + "\n")["state"] == "incomplete"
    cut = status().split("Server db:")[0]
    assert _all(cut + LEGEND + "\n")["state"] == "incomplete"
    no_header = status().replace(HEADER + "\n", "")
    assert _all(no_header)["state"] == "incomplete"


def test_unreadable_row_is_counted_dropped_and_incomplete():
    hostile = ROW_802.replace("port18", "port18;exec<script>")
    bad_vlan = ROW_802.replace("  52  ", "  5000  ")
    bad_ip = ROW_802.replace("192.0.2.10", "300.0.2.10")
    bad_mac = ROW_802.replace("00:00:5E:00:53:01", "00:00:5E:00:53")
    for row in (hostile, bad_vlan, bad_ip, bad_mac, "garbage line"):
        result = _all(status(rows=(ROW_768, row)))
        assert result["state"] == "incomplete", row
        assert result["unreadable_rows"] == 1 and result["total_bindings"] == 1
        assert [b["mac"] for b in result["bindings"]] == ["00:00:5e:00:53:02"]
        assert "exec" not in json.dumps(result) and "<script>" not in json.dumps(result)


def test_ipv6_rows_are_flagged_not_parsed():
    result = _all(status(client6=(HEADER, "       00:00:5e:00:53:09  52  2001:db8::9  0:0:15:0  0:0:14:0  port9  2001:db8::1"),))
    assert result["state"] == "ok" and result["ipv6_rows_present"] is True and result["total_bindings"] == 1


def test_pages_split_bindings_once_each():
    text = status(rows=(ROW_768, ROW_802))
    raw = text.encode("utf-8")
    cut = raw.index(b"\n       00:00:5E:00:53:01") + 1
    first, second = summarize(text, 0, cut), summarize(text, cut, len(raw))
    assert first["total_bindings"] == second["total_bindings"] == 2
    assert [b["ip"] for b in first["bindings"]] == ["198.51.100.2"]
    assert [b["ip"] for b in second["bindings"]] == ["192.0.2.10"]


def _fake(monkeypatch, body):
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        return 0, FORTIOS_STATUS if command == engine._IDENTITY_COMMAND else body

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    return sent


def _switch_target(query):
    return replace(_target("fortinet", query), read_inventory={"managed_switches": (A,)})


def test_ssh_read_attaches_dhcp_bindings(monkeypatch):
    sent = _fake(monkeypatch, status() + PASSWORD)
    answer = engine.ssh_read(_switch_target(DHCP_BINDINGS_QUERY), "fortinet", DHCP_BINDINGS_QUERY,
                             {"managed_switch": A}, 0, 16000)
    assert answer["ok"] is True
    assert sent[-1] == f"diagnose switch-controller switch-info dhcp-snooping status {A}"
    assert answer["dhcp_bindings"]["state"] == "ok"
    assert answer["dhcp_bindings"]["bindings"][0]["port"] == "port18"
    assert PASSWORD not in json.dumps(answer)


def test_ssh_read_second_page_carries_its_own_bindings(monkeypatch):
    text = status(rows=(ROW_768,) * 6 + (ROW_802,))
    _fake(monkeypatch, text)
    cut = text.encode("utf-8").index(b"\n       00:00:5E:00:53:01") + 1
    first = engine.ssh_read(_switch_target(DHCP_BINDINGS_QUERY), "fortinet", DHCP_BINDINGS_QUERY,
                            {"managed_switch": A}, 0, cut)
    second = engine.ssh_read(_switch_target(DHCP_BINDINGS_QUERY), "fortinet", DHCP_BINDINGS_QUERY,
                             {"managed_switch": A}, first["next_offset"], 16000, first["content_sha256"])
    seen = [b["ip"] for page in (first, second) for b in page["dhcp_bindings"]["bindings"]]
    assert first["next_offset"] == cut and second["next_offset"] is None
    assert sorted(seen) == ["192.0.2.10"] + ["198.51.100.2"] * 6
    assert first["dhcp_bindings"]["total_bindings"] == second["dhcp_bindings"]["total_bindings"] == 7


def test_settings_query_and_other_queries_get_no_dhcp_bindings(monkeypatch):
    sent = _fake(monkeypatch, status())
    for query in ("switch_dhcp_snooping", "switch_fan_health"):
        answer = engine.ssh_read(_switch_target(query), "fortinet", query, {"managed_switch": A}, 0, 16000)
        assert answer["ok"] is True and "dhcp_bindings" not in answer
    assert f"diagnose switch-controller switch-info dhcp-snooping database {A}" in sent


def test_helper_docs_explain_dhcp_binding_states():
    text = Path(__file__).resolve().parents[1].joinpath("docs/tools.md").read_text(encoding="utf-8")
    section = text[text.index("## FortiSwitch DHCP snooping bindings"):]
    section = section[:section.index("\n## ", 1)] if "\n## " in section[1:] else section
    for word in ("`ok`", "`empty`", "`incomplete`", "`unreadable_rows`", "`ipv6_rows_present`",
                 "`total_bindings`", "`next_offset`", "`switch_dhcp_snooping`", "Host Name"):
        assert word in section, word
    assert "dhcp_bindings" in QUERIES[DHCP_BINDINGS_QUERY].description
