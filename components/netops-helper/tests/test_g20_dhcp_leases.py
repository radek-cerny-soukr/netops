"""G20 (1.0.12, FP-12): all DHCP leases of a FortiGate in one read.

Real RO captures of the lab FG-60F, FortiOS 7.6.8 build3744, 2026-11-20 (anonymised, see the README next to the
fixtures). The SSH transport is faked; the captured text goes through the real engine and parser. Variants made by
cutting or editing a capture are marked as derived.
"""
from __future__ import annotations

import json
from pathlib import Path

from conftest import FORTIOS_STATUS, PASSWORD, _target
from netops_helper import engine, proxy, switch_dhcp
from netops_helper.query_catalog.fortinet import QUERIES
from netops_helper.read_policy import _validate_query_command

REAL = Path(__file__).parent / "fixtures/real/fortinet/fortigate60f_7.6.8_g20"
CAPTURES = json.loads((REAL / "captures.json").read_text())
ALL = CAPTURES["lease_list_all"]


def _fake_ssh(monkeypatch, body, rc=0):
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        return (0, FORTIOS_STATUS) if command == engine._IDENTITY_COMMAND else (rc, body)

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    return sent


def _read(offset=0, max_bytes=16_000, digest=None):
    return engine.ssh_read(_target("fortinet", "dhcp_leases_all"), "fortinet", "dhcp_leases_all", None,
                           offset, max_bytes, digest)


def test_catalogue_entry_is_the_fixed_read_only_command_and_is_proxied():
    query = QUERIES["dhcp_leases_all"]
    assert (query.command, dict(query.slots), query.high_volume, query.empty_allowed) == (
        "execute dhcp lease-list", {}, True, True)
    _validate_query_command("fortinet", query.command)
    assert "dhcp_leases_all" in proxy.READ_QUERY_NAMES["fortinet"]
    assert "dhcp_leases_all" not in proxy.READ_QUERY_SLOTS["fortinet"]


def test_ssh_read_lists_every_lease_of_every_interface(monkeypatch):
    sent = _fake_ssh(monkeypatch, ALL)
    answer = _read()
    assert answer["ok"] is True and answer["next_offset"] is None
    assert sent[-1] == "execute dhcp lease-list"
    leases = answer["dhcp_leases"]
    assert (leases["state"], leases["total_leases"], leases["unreadable_lines"]) == ("ok", 2, 0)
    assert leases["interfaces"] == [{"interface": "_default", "leases": 1}, {"interface": "fortilink", "leases": 1}]
    assert leases["leases"] == [
        {"interface": "_default", "ip": "192.0.2.2", "mac": "00:00:5e:00:53:01", "hostname": "host01", "vci": None,
         "ssid": None, "ap": None, "server_id": 6, "expiry": "Wed Nov 25 21:07:19 2026"},
        {"interface": "fortilink", "ip": "198.51.100.3", "mac": "00:00:5e:00:53:02", "hostname": "host02",
         "vci": "FortiSwitch-108E", "ssid": None, "ap": None, "server_id": 2, "expiry": "Wed Nov 25 22:03:32 2026"},
    ]
    assert PASSWORD not in json.dumps(answer)


def test_one_interface_section_parses_the_same_way():
    text = CAPTURES["lease_list_fortilink"]
    result = switch_dhcp.fortios_leases(text, 0, len(text.encode()))
    assert (result["state"], result["total_leases"]) == ("ok", 1)
    assert result["leases"][0]["vci"] == "FortiSwitch-108E"


def test_empty_output_is_an_empty_lease_table_not_an_error(monkeypatch):
    assert CAPTURES["lease_list_internal_empty"] == ""
    _fake_ssh(monkeypatch, CAPTURES["lease_list_internal_empty"])
    answer = _read()
    assert answer["ok"] is True
    assert (answer["dhcp_leases"]["state"], answer["dhcp_leases"]["total_leases"]) == ("empty", 0)


def test_page_window_returns_only_its_own_leases_with_whole_output_counts():
    # the ssh_read page is a byte window of the output; the counts always cover the whole output
    second_row = ALL.index("  198.51.100.3")
    first = switch_dhcp.fortios_leases(ALL, 0, second_row)
    rest = switch_dhcp.fortios_leases(ALL, second_row, len(ALL.encode()))
    assert [item["ip"] for item in first["leases"]] == ["192.0.2.2"]
    assert [item["ip"] for item in rest["leases"]] == ["198.51.100.3"]
    assert first["total_leases"] == rest["total_leases"] == 2


def test_cut_output_is_incomplete_not_a_shorter_table():
    # derived: the real capture cut in the middle of the second lease row
    cut = ALL[:ALL.index("host02") + 8]
    result = switch_dhcp.fortios_leases(cut, 0, len(cut.encode()))
    assert (result["state"], result["total_leases"], result["unreadable_lines"]) == ("incomplete", 1, 1)


def test_section_without_its_header_is_incomplete():
    # derived: the header line of the second section is missing
    lines = ALL.splitlines(keepends=True)
    text = "".join(lines[:4] + lines[5:])
    result = switch_dhcp.fortios_leases(text, 0, len(text.encode()))
    assert result["state"] == "incomplete" and result["total_leases"] == 1


def test_unknown_line_shape_and_a_cell_filling_its_column_are_incomplete():
    # derived: an extra line, and a host name that would run into the next column
    extra = ALL + "  something new\n"
    assert switch_dhcp.fortios_leases(extra, 0, len(extra.encode()))["unreadable_lines"] == 1
    long_name = ALL.replace("host02              FortiSwitch", "host02-xxxxxxxxxxxxxFortiSwitch")
    result = switch_dhcp.fortios_leases(long_name, 0, len(long_name.encode()))
    assert (result["state"], result["total_leases"]) == ("incomplete", 1)


def test_account_without_cli_exec_gets_a_cli_error_without_leases(monkeypatch):
    _fake_ssh(monkeypatch, CAPTURES["lease_list_refused_cli_exec"])
    answer = _read()
    assert answer["ok"] is False and answer["error_code"] == "device_cli_error"
    assert "dhcp_leases" not in answer


def test_unknown_interface_answer_is_not_a_lease_table():
    result = switch_dhcp.fortios_leases(CAPTURES["lease_list_bad_interface"], 0, 100)
    assert (result["state"], result["total_leases"]) == ("incomplete", 0)


def test_other_queries_get_no_dhcp_leases_object(monkeypatch):
    _fake_ssh(monkeypatch, ALL)
    answer = engine.ssh_read(_target("fortinet", "arp_table"), "fortinet", "arp_table", None, 0, 16_000)
    assert "dhcp_leases" not in answer
