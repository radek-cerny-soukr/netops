"""G11 (1.0.12): FortiGate-local normalized tables (FP-07), all interfaces with link state (FP-08), the whole IPv6
routing table (FG-21), the routing information base with inactive routes (FG-22) and BGP neighbor detail (FG-23).

Real read-only captures of 2026-11-18 (anonymised, see fixtures/real/fortinet/g11_20261118/README.md): lab
FortiGate-60F 7.6.8 build3744 (`60f`), IT-case FortiGate-80F 8.0.2 build0251 with three iBGP peers and one BGP route
that loses to a connected route (`kufr`), and the IPv6 table of a FortiGate-80F 8.0.2 with a static default route via
a link-local gateway and kernel routes (`80f`). Only the SSH transport is faked; the captured text goes through the
real engine, rendering, paging and parsers. Mutations of a real capture are marked as such.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from conftest import FORTIOS_STATUS, PASSWORD, _target
from netops_helper import engine, fortios_vdom, proxy, read_policy, tables
from netops_helper.query_catalog import READ_QUERIES
from netops_helper.query_catalog.model import Slot
from netops_helper.read_policy import _validate_query_command

CAPTURES = json.loads((Path(__file__).parent / "fixtures/real/fortinet/g11_20261118/captures.json").read_text())
SIXTY, KUFR, EIGHTY = CAPTURES["60f"], CAPTURES["kufr"], CAPTURES["80f"]
LIVE = json.loads((Path(__file__).parent / "fixtures/real/fortinet/g11_20261118/r2-live.json").read_text())
NEW = {
    "ipv6_routing_table": ("get router info6 routing-table", {}),
    "routing_table_database": ("get router info routing-table database", {}),
    "ipv6_routing_table_database": ("get router info6 routing-table database", {}),
    "bgp_neighbor_detail": ("get router info bgp neighbors {peer}", {"peer": Slot("addresses", "ipv4_address")}),
    "ipv6_bgp_neighbor_detail": ("get router info6 bgp neighbors {peer6}",
                                 {"peer6": Slot("addresses", "ipv6_address")}),
    "interface_list": ("diagnose netlink interface list", {}),
}


def _fake(monkeypatch, body, rc=0):
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        if command == engine._IDENTITY_COMMAND:
            return 0, FORTIOS_STATUS
        return rc, body[command] if isinstance(body, dict) else body

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    return sent


def _read(query, parameters=None, inventory=None, offset=0, max_bytes=16_000, digest=None):
    auth = replace(_target("fortinet", query), read_inventory=inventory or {})
    return engine.ssh_read(auth, "fortinet", query, parameters, offset, max_bytes, digest)


def _table(table, queries, inventory=None, **options):
    auth = replace(_target("fortinet", queries[0]), enabled_queries=tuple(queries), read_inventory=inventory or {})
    return engine.switch_read(auth, table, **options)


# ---------------------------------------------------------------- catalogue and registration

@pytest.mark.parametrize("query", sorted(NEW))
def test_new_queries_are_fixed_read_only_templates_registered_in_the_proxy(query):
    command, slots = NEW[query]
    entry = READ_QUERIES["fortinet"][query]
    assert (entry.command, dict(entry.slots), entry.high_volume) == (command, slots, True)
    assert entry.optional_slots == frozenset(slots)
    _validate_query_command("fortinet", command.split(" {")[0])
    assert query in proxy.READ_QUERY_NAMES["fortinet"]
    assert proxy.READ_QUERY_SLOTS["fortinet"].get(query, {}) == {
        name: {"inventory": slot.inventory, "kind": slot.kind, "optional": True} for name, slot in slots.items()}


def test_the_bgp_peer_argument_is_optional_and_only_an_enrolled_address_of_its_family():
    inventory = {"addresses": ("203.0.113.254", "2001:db8::1")}
    render = lambda query, parameters: read_policy.render_read_query("fortinet", query, parameters, inventory)[1]
    assert render("bgp_neighbor_detail", {}) == "get router info bgp neighbors"
    assert render("bgp_neighbor_detail", {"peer": "203.0.113.254"}) == "get router info bgp neighbors 203.0.113.254"
    assert render("ipv6_bgp_neighbor_detail", {"peer6": "2001:db8::1"}) == "get router info6 bgp neighbors 2001:db8::1"
    for query, value in (("bgp_neighbor_detail", "203.0.113.253"), ("bgp_neighbor_detail", "2001:db8::1"),
                         ("ipv6_bgp_neighbor_detail", "203.0.113.254")):
        with pytest.raises(ValueError):
            render(query, {query.startswith("ipv6") and "peer6" or "peer": value})


def test_the_interface_list_is_labelled_device_wide_in_multi_vdom():
    assert fortios_vdom.DATA_SCOPES["interface_list"] == "device"
    assert "interface_list" in fortios_vdom.VDOM_ADMIN_REFUSED_QUERIES


# ---------------------------------------------------------------- FG-21: whole IPv6 routing table

def test_route_table_ipv6_reads_the_whole_table_of_the_80f(monkeypatch):
    sent = _fake(monkeypatch, EIGHTY["ipv6_routing_table"])
    result = _table("route", ["ipv6_routing_table"], address_family="ipv6")
    assert sent[-1] == "get router info6 routing-table"
    assert result["ok"] is True and result["status"] == "ok" and result["unparsed"] == []
    assert result["records"] == [
        {"prefix": "::/0", "next_hop": "fe80::10", "interface": "wan1", "protocol": "static", "vrf": "default"},
        {"prefix": "::1/128", "next_hop": None, "interface": "root", "protocol": "connected", "vrf": "default"},
        {"prefix": "2001:db8:1::10/128", "next_hop": None, "interface": "wan1", "protocol": "connected", "vrf": "default"},
        {"prefix": "2001:db8:2::/64", "next_hop": None, "interface": "IPV6", "protocol": "connected", "vrf": "default"}]
    assert result["coverage"]["complete"] is True


@pytest.mark.parametrize("capture", [SIXTY, KUFR], ids=["60f-768", "80f-802-kufr"])
def test_a_firewall_with_only_the_ipv6_loopback_lists_it(monkeypatch, capture):
    _fake(monkeypatch, capture["ipv6_routing_table"])
    result = _table("route", ["ipv6_routing_table"], address_family="ipv6")
    assert result["status"] == "ok" and result["records"] == [
        {"prefix": "::1/128", "next_hop": None, "interface": "root", "protocol": "connected", "vrf": "default"}]


def test_an_unknown_ipv6_route_line_is_kept_unparsed_not_dropped(monkeypatch):
    # Mutation of the real 80F capture: one route line in a shape that was not measured.
    _fake(monkeypatch, EIGHTY["ipv6_routing_table"].replace("via fe80::10, wan1, 03w5d09h, [1024/1]",
                                                            "via fe80::10 wan1 03w5d09h"))
    result = _table("route", ["ipv6_routing_table"], address_family="ipv6")
    assert result["status"] == "unparsed" and result["coverage"]["complete"] is False
    assert [line["text"].split()[1] for line in result["unparsed"]] == ["::/0"]


def test_route_table_address_family_requests():
    assert tables.request("fortinet", "route", address_family="ipv6") == ("ipv6_routing_table", {}, {})
    assert tables.request("fortinet", "route", address_family="ipv4")[0] == "routing_table"
    assert tables.request("fortinet", "route", ip="2001:db8::1", address_family="ipv6") == (
        "ipv6_route_lookup", {"address": "2001:db8::1"}, {})
    with pytest.raises(ValueError):
        tables.request("fortinet", "route", ip="192.0.2.1", address_family="ipv6")


# ---------------------------------------------------------------- FG-22: routing information base

def test_the_rib_shows_the_bgp_route_that_lost_to_a_connected_route(monkeypatch):
    sent = _fake(monkeypatch, KUFR["routing_table_database"])
    answer = _read("routing_table_database")
    assert answer["ok"] is True and sent[-1] == "get router info routing-table database"
    rib = answer["route_database"]
    assert (rib["state"], rib["total_entries"], rib["selected"], rib["fib"], rib["not_selected"]) == ("ok", 28, 27, 27, 1)
    assert rib["inactive"] == [{
        "prefix": "203.0.113.232/24", "protocol": "bgp", "distance": 200, "gateway": "192.0.2.254",
        "interface": "HUB-O1", "fib": False, "vrf": "default",
        "selected_instead": [{"protocol": "connected", "distance": None, "gateway": None, "interface": "wan1"}] * 2}]
    default = [entry for entry in rib["entries"] if entry["prefix"] == "0.0.0.0/0"]
    assert [(e["gateway"], e["interface"], e["selected"], e["fib"]) for e in default] == [
        ("203.0.113.249", "wan1", True, True), ("203.0.113.248", "LTE-OP1", True, True),
        ("203.0.113.247", "LTE-OP2", True, True)]
    tunnel = next(entry for entry in rib["entries"] if entry["prefix"] == "192.0.2.0/24")
    assert (tunnel["protocol"], tunnel["distance"], tunnel["gateway"], tunnel["interface"]) == (
        "static", 5, "203.0.113.242", "HUB-O1")
    assert PASSWORD not in json.dumps(answer)


def test_the_ipv6_rib_shows_kernel_routes_in_the_fib_that_were_not_selected(monkeypatch):
    sent = _fake(monkeypatch, EIGHTY["ipv6_routing_table_database"])
    rib = _read("ipv6_routing_table_database")["route_database"]
    assert sent[-1] == "get router info6 routing-table database"
    assert (rib["state"], rib["total_entries"], rib["selected"], rib["fib"], rib["not_selected"]) == ("ok", 6, 4, 6, 2)
    assert rib["inactive"] == [
        {"prefix": "::/0", "protocol": "kernel", "distance": None, "gateway": "fe80::10", "interface": "wan1",
         "fib": True, "vrf": "default",
         "selected_instead": [{"protocol": "static", "distance": 5, "gateway": "fe80::10", "interface": "wan1"}]},
        {"prefix": "2001:db8:1::/64", "protocol": "kernel", "distance": None, "gateway": None, "interface": "wan1",
         "fib": True, "vrf": "default", "selected_instead": []}]


def test_the_60f_rib_has_every_route_selected(monkeypatch):
    _fake(monkeypatch, SIXTY["routing_table_database"])
    rib = _read("routing_table_database")["route_database"]
    assert (rib["state"], rib["total_entries"], rib["selected"], rib["not_selected"], rib["inactive"]) == (
        "ok", 13, 13, 0, [])
    _fake(monkeypatch, SIXTY["ipv6_routing_table_database"])
    rib = _read("ipv6_routing_table_database")["route_database"]
    assert (rib["state"], [e["prefix"] for e in rib["entries"]]) == ("ok", ["::1/128"])


def test_an_unknown_rib_line_makes_the_database_incomplete(monkeypatch):
    # Mutation of the real kufr capture: the BGP entry in a shape that was not measured.
    _fake(monkeypatch, KUFR["routing_table_database"].replace("(recursive via HUB-O1", "(unresolved via HUB-O1"))
    rib = _read("routing_table_database")["route_database"]
    assert (rib["state"], rib["unreadable_lines"], rib["not_selected"]) == ("incomplete", 1, 0)


def test_rib_pages_carry_their_own_entries_with_whole_output_counts(monkeypatch):
    _fake(monkeypatch, KUFR["routing_table_database"])
    first = _read("routing_table_database", max_bytes=1200)
    assert first["next_offset"] is not None
    second = _read("routing_table_database", offset=first["next_offset"], digest=first["content_sha256"])
    one, two = first["route_database"], second["route_database"]
    assert one["total_entries"] == two["total_entries"] == 28 and one["inactive"] == two["inactive"]
    assert len(one["entries"]) + len(two["entries"]) == 28 and one["entries"] and two["entries"]


# ---------------------------------------------------------------- FG-23: BGP neighbor detail

def test_bgp_neighbor_detail_of_every_peer(monkeypatch):
    sent = _fake(monkeypatch, KUFR["bgp_neighbors"])
    answer = _read("bgp_neighbor_detail")
    assert answer["ok"] is True and sent[-1] == "get router info bgp neighbors"
    bgp = answer["bgp_neighbors"]
    assert (bgp["state"], bgp["total_neighbors"], bgp["established"], bgp["unreadable_lines"]) == ("ok", 3, 3, 0)
    first, second, third = bgp["neighbors"]
    assert (first["neighbor"], first["remote_as"], first["local_as"], first["link"], first["state"], first["up_for"]) == (
        "192.0.2.254", "65000", "65000", "internal", "Established", "2d22h02m")
    assert (first["hold_time"], first["keepalive"], first["configured_hold_time"], first["configured_keepalive"]) == (
        3, 1, 3, 1)
    assert (first["last_reset"], first["last_reset_reason"], first["connections_dropped"]) == (None, None, 0)
    assert (second["last_reset"], second["last_reset_reason"], second["last_notification"]) == (
        "2d20h07m", "BGP Notification sent", "CeaseUnspecified Error Subcode")
    assert (second["notifications_sent"], second["connections_established"], second["connections_dropped"]) == (2, 3, 2)
    assert (third["hold_time"], third["last_reset"]) == (10, "19:43:51")
    assert first["capabilities"]["Route refresh"] == "advertised and received (old and new)"
    assert first["capabilities"]["Address family IPv4 Unicast"] == "advertised and received"
    assert first["address_families"]["IPv4 Unicast"] == {
        "accepted_prefixes": 1, "prefixes_in_rib": 1, "announced_prefixes": 1}
    assert len(first["address_families"]) == 5
    assert (first["local_address"], first["nexthop_interface"]) == ("192.0.2.1", "HUB-O1")


def test_bgp_neighbor_detail_of_one_enrolled_peer(monkeypatch):
    sent = _fake(monkeypatch, KUFR["bgp_neighbors_peer"])
    answer = _read("bgp_neighbor_detail", {"peer": "203.0.113.254"}, {"addresses": ("203.0.113.254",)})
    assert sent[-1] == "get router info bgp neighbors 203.0.113.254"
    bgp = answer["bgp_neighbors"]
    assert (bgp["state"], bgp["total_neighbors"]) == ("ok", 1)
    assert (bgp["neighbors"][0]["neighbor"], bgp["neighbors"][0]["last_reset_reason"]) == (
        "203.0.113.254", "BGP Notification sent")


def test_the_ipv6_address_family_view_of_the_peers(monkeypatch):
    sent = _fake(monkeypatch, KUFR["ipv6_bgp_neighbors"])
    bgp = _read("ipv6_bgp_neighbor_detail")["bgp_neighbors"]
    assert sent[-1] == "get router info6 bgp neighbors"
    assert (bgp["state"], bgp["total_neighbors"], bgp["established"]) == ("ok", 3, 3)


def test_an_unknown_peer_is_named_not_an_empty_list(monkeypatch):
    _fake(monkeypatch, KUFR["bgp_neighbors_peer_absent"])
    answer = _read("bgp_neighbor_detail", {"peer": "203.0.113.200"}, {"addresses": ("203.0.113.200",)})
    assert answer["ok"] is True
    assert answer["bgp_neighbors"] == {"state": "no_such_neighbor", "total_neighbors": 0, "unreadable_lines": 0,
                                       "neighbors": []}


@pytest.mark.parametrize("query", ["bgp_neighbor_detail", "ipv6_bgp_neighbor_detail"])
def test_a_firewall_without_bgp_answers_an_empty_successful_read(monkeypatch, query):
    _fake(monkeypatch, SIXTY["bgp_neighbors"] if query.startswith("bgp") else SIXTY["ipv6_bgp_neighbors"])
    answer = _read(query)
    assert answer["ok"] is True and answer["bgp_neighbors"]["state"] == "empty"
    assert answer["bgp_neighbors"]["neighbors"] == []


def test_a_refused_bgp_read_is_an_error_without_neighbors(monkeypatch):
    # The device text of a refused diagnose/get (G13 capture of the same RO account): `command parse error`.
    _fake(monkeypatch, "command parse error before 'neighbors'\nCommand fail. Return code -61\n")
    answer = _read("bgp_neighbor_detail")
    assert answer["ok"] is False and "bgp_neighbors" not in answer


def test_an_unknown_bgp_line_makes_the_detail_incomplete(monkeypatch):
    # Mutation of the real kufr capture: one line of a shape that was not measured.
    _fake(monkeypatch, KUFR["bgp_neighbors_peer"].replace("Default weight 200", "Update source is loopback0"))
    bgp = _read("bgp_neighbor_detail", {"peer": "203.0.113.254"}, {"addresses": ("203.0.113.254",)})["bgp_neighbors"]
    assert (bgp["state"], bgp["unreadable_lines"], bgp["total_neighbors"]) == ("incomplete", 1, 1)


# ---------------------------------------------------------------- FP-08: every interface with link state

def _interface_reads(text, box):
    return {"diagnose netlink interface list": text,
            "diagnose netlink device list": LIVE[box]["netlink-device"],
            "diagnose netlink interface packet-rate": LIVE[box]["packet-rate"]}


@pytest.mark.parametrize("box,total,up", [("60f", 27, 18), ("kufr", 31, 26)])
def test_the_interface_list_gives_link_state_of_every_logical_interface(monkeypatch, box, total, up):
    sent = _fake(monkeypatch, _interface_reads(CAPTURES[box]["interface_list"], box))
    answer = _read("interface_list", max_bytes=48_000)
    assert [command for command in sent if command != engine._IDENTITY_COMMAND] == [
        "diagnose netlink interface list", "diagnose netlink device list", "diagnose netlink interface packet-rate",
        "diagnose netlink device list"]
    listing = answer["interfaces"]
    assert (listing["state"], listing["total_interfaces"], listing["link_up"], listing["link_down"]) == (
        "ok", total, up, total - up)
    rows = {row["name"]: row for row in listing["interfaces"]}
    assert len(rows) == total
    assert (rows["fortilink"]["role"], rows["fortilink"]["link"]) == ("aggregate", "up")
    assert [(rows[m]["master"], rows[m]["role"]) for m in ("a", "b")] == [("fortilink", "aggregate_member")] * 2
    assert rows["internal"]["admin_status"] == "up" and rows["internal"]["link"] == "down"  # no_carrier
    assert (rows["wan1"]["admin_status"], rows["wan1"]["link"], rows["wan1"]["mtu"]) == ("up", "up", 1500)


def test_the_kufr_interface_list_keeps_aliases_and_tunnels(monkeypatch):
    _fake(monkeypatch, _interface_reads(KUFR["interface_list"], "kufr"))
    rows = {row["name"]: row for row in _read("interface_list")["interfaces"]["interfaces"]}
    assert (rows["quarantine"]["alias"], rows["quarantine"]["link"]) == ("quarantine.fortilink", "up")
    assert (rows["HUB-O1"]["role"], rows["HUB-O1"]["mtu"], rows["HUB-O1"]["link"]) == ("point_to_point", 1402, "up")
    assert rows["wan1"]["alias"] is None


def test_the_60f_interface_list_names_vlans_and_a_down_member(monkeypatch):
    _fake(monkeypatch, _interface_reads(SIXTY["interface_list"], "60f"))
    rows = {row["name"]: row for row in _read("interface_list", max_bytes=48_000)["interfaces"]["interfaces"]}
    assert (rows["b"]["admin_status"], rows["b"]["link"]) == ("down", "down")
    assert (rows["PVE-MGMT"]["link"], rows["root"]["role"], rows["modem"]["admin_status"]) == ("up", "loopback", "down")


def test_a_truncated_interface_block_makes_the_list_incomplete(monkeypatch):
    # Mutation of the real 60F capture: the state line of wan2 is missing.
    text = SIXTY["interface_list"].replace(
        "ref=25 state=start present fw_flags=400 flags=up broadcast run multicast \n", "", 1)
    _fake(monkeypatch, _interface_reads(text, "60f"))
    listing = _read("interface_list", max_bytes=48_000)["interfaces"]
    assert (listing["state"], listing["interfaces_without_state_line"]) == ("incomplete", 1)


# ---------------------------------------------------------------- FP-07: FortiGate-local normalized tables

def test_bgp_peer_table_of_the_kufr(monkeypatch):
    sent = _fake(monkeypatch, KUFR["bgp_summary"])
    result = _table("bgp_peer", ["bgp_summary"])
    assert sent[-1] == "get router info bgp summary"
    assert result["status"] == "ok" and result["unparsed"] == [] and result["coverage"]["complete"] is True
    assert result["records"] == [
        {"neighbor": address, "remote_as": "65000", "state": "Established", "prefixes": 1, "vrf": "default"}
        for address in ("192.0.2.254", "203.0.113.254", "203.0.113.253")]
    _fake(monkeypatch, KUFR["ipv6_bgp_summary"])
    result = _table("bgp_peer", ["ipv6_bgp_summary"], address_family="ipv6")
    assert result["status"] == "ok" and [row["prefixes"] for row in result["records"]] == [0, 0, 0]


@pytest.mark.parametrize("table,query,key", [("bgp_peer", "bgp_summary", "bgp_summary"),
                                             ("ospf_neighbor", "ospf_neighbors", "ospf_neighbors")])
def test_routing_tables_of_a_firewall_without_the_protocol_are_empty(monkeypatch, table, query, key):
    _fake(monkeypatch, SIXTY[key])
    result = _table(table, [query])
    assert result["ok"] is True and result["status"] == "empty" and result["records"] == []


def test_the_kufr_without_ospf_has_an_empty_neighbor_table(monkeypatch):
    sent = _fake(monkeypatch, KUFR["ospf_neighbors"])
    result = _table("ospf_neighbor", ["ospf_neighbors"])
    assert sent[-1] == "get router info ospf neighbor all" and result["status"] == "empty"


def test_lag_of_an_enrolled_aggregate(monkeypatch):
    sent = _fake(monkeypatch, SIXTY["lacp_detail_fortilink"])
    result = _table("lag", ["lacp_detail"], {"interfaces": ("fortilink", "wan1")}, interface="fortilink")
    assert sent[-1] == "diagnose netlink aggregate name fortilink show"
    assert result["status"] == "ok" and result["unparsed"] == [] and result["coverage"]["complete"] is True
    assert result["records"] == [{"name": "fortilink", "protocol": "lacp", "status": "up", "members": [
        {"port": "a", "state": "bundled"}, {"port": "b", "state": "down"}]}]


def test_lag_of_an_interface_that_is_no_aggregate_is_empty(monkeypatch):
    _fake(monkeypatch, SIXTY["lacp_detail_wan1"])
    result = _table("lag", ["lacp_detail"], {"interfaces": ("fortilink", "wan1")}, interface="wan1")
    assert result["status"] == "empty" and result["records"] == []


def test_interface_errors_of_one_enrolled_interface(monkeypatch):
    sent = _fake(monkeypatch, SIXTY["interface_details_wan1"])
    result = _table("interface_errors", ["interface_details"], {"interfaces": ("wan1",)}, interface="wan1")
    assert sent[-1] == "diagnose netlink interface list wan1"
    assert result["status"] == "ok" and result["unparsed"] == []
    row = result["records"][0]
    assert (row["port"], row["rx_errors"], row["tx_errors"], row["crc"], row["discards_in"], row["discards_out"]) == (
        "wan1", 0, 0, 0, 0, 0)
    assert result["counter_baseline"]


def test_interface_errors_count_what_the_device_prints(monkeypatch):
    # Mutation of the real 60F capture: non-zero error, drop and CRC counters.
    text = SIXTY["interface_details_fortilink"].replace("rxe=0 txe=0 rxd=0 txd=0", "rxe=7 txe=1 rxd=3 txd=2").replace(
        "rxc=0", "rxc=5")
    _fake(monkeypatch, text)
    row = _table("interface_errors", ["interface_details"], {"interfaces": ("fortilink",)},
                 interface="fortilink")["records"][0]
    assert (row["port"], row["rx_errors"], row["tx_errors"], row["crc"], row["discards_in"], row["discards_out"]) == (
        "fortilink", 7, 1, 5, 3, 2)


def test_the_interface_filter_applies_to_the_physical_table(monkeypatch):
    # The 80F capture of 2026-11-10 (the G11 60F capture has anonymiser-widened `ip:` lines the parser keeps unparsed).
    real = Path(__file__).parent / "fixtures/real/fortinet/fortigate80f_8.0.2_build0251/local_20261110/physical.txt"
    _fake(monkeypatch, real.read_text())
    result = _table("interface", ["physical_interfaces"], interface="a")
    assert result["status"] == "ok" and [row["name"] for row in result["records"]] == ["a"]
    assert result["records"][0]["oper_status"] == "up" and result["coverage"]["parsed_records"] == 11


@pytest.mark.parametrize("table", ["lag", "interface_errors"])
def test_aggregate_and_counter_tables_need_an_interface(table):
    with pytest.raises(ValueError, match="interface is required"):
        tables.request("fortinet", table)


def test_fortigate_local_switch_tables_use_named_reads():
    assert tables.request("fortinet", "stp_port") == ("local_stp_ports", {}, {})
    assert tables.request("fortinet", "port_vlan") == ("local_switch_vlans", {}, {})


def test_filters_outside_their_table_are_refused():
    with pytest.raises(ValueError):
        tables.request("fortinet", "bgp_peer", interface="wan1")
    with pytest.raises(ValueError):
        tables.request("fortinet", "ospf_neighbor", address_family="ipv6")
    with pytest.raises(ValueError):
        tables.request("fortinet", "lag", interface="wan1; show")


# ---------------------------------------------------------------- live findings (task 488 live run on the IT-case)

def test_kufr_802_interface_counters_with_the_session_line(monkeypatch):
    # The 8.0.2 netlink detail ends with `session_count4=..., session_count6=...` (live capture 2026-11-18).
    sent = _fake(monkeypatch, KUFR["interface_details_wan1"])
    result = _table("interface_errors", ["interface_details"], {"interfaces": ("wan1",)}, interface="wan1")
    assert sent[-1] == "diagnose netlink interface list wan1"
    assert result["status"] == "ok" and result["unparsed"] == [] and result["records"][0]["rx_errors"] == 0


def test_kufr_802_lag_with_both_members_bundled(monkeypatch):
    _fake(monkeypatch, KUFR["lacp_detail_fortilink"])
    result = _table("lag", ["lacp_detail"], {"interfaces": ("fortilink",)}, interface="fortilink")
    assert result["status"] == "ok" and result["unparsed"] == []
    assert result["records"] == [{"name": "fortilink", "protocol": "lacp", "status": "up", "members": [
        {"port": "a", "state": "bundled"}, {"port": "b", "state": "bundled"}]}]


def _section(queries, inventory):
    from types import SimpleNamespace
    return SimpleNamespace(catalog_platform=lambda: "fortinet", ssh_platform="fortios", enabled_queries=queries,
                           read_inventory=inventory, device_types=("firewall",), egress={})


def test_the_proxy_passes_an_enrolled_aggregate_to_the_lag_table():
    section = _section(("lacp_detail",), {"interfaces": ("fortilink",)})
    args = {"target": "lab-kufr", "table": "lag", "interface": "fortilink"}
    assert proxy.Proxy._validate_tool_arguments("switch_read", args) == args
    proxy.Proxy._authorize_tool("switch_read", args, None, section)
    with pytest.raises(proxy.PolicyScopeError):
        proxy.Proxy._authorize_tool("switch_read", dict(args, interface="internal"), None, section)


@pytest.mark.parametrize("change,field", [({"table": "lag", "interface": None}, "interface"),
                                          ({"table": "ospf_neighbor", "address_family": "ipv6"}, "address_family"),
                                          ({"table": "bgp_peer", "interface": "wan1"}, "table")])
def test_the_proxy_names_the_field_of_a_refused_fortigate_table_request(change, field):
    section = _section(("lacp_detail", "ospf_neighbors", "bgp_summary"), {"interfaces": ("fortilink", "wan1")})
    args = {key: value for key, value in dict({"target": "lab-kufr"}, **change).items() if value is not None}
    with pytest.raises(proxy.ToolArgumentsError) as refused:
        proxy.Proxy._authorize_tool("switch_read", args, None, section)
    assert refused.value.data["field"] == field


def test_intent_keeps_the_enrolled_fortios_aggregate_name_with_underscore(monkeypatch):
    name = "fixture_lag"
    body = KUFR["lacp_detail_fortilink"].replace("fortilink", name)
    sent = _fake(monkeypatch, body)

    def read(args):
        assert args["target"] == "wire-test"
        return _table("lag", ["lacp_detail"], {"interfaces": (name,)}, interface=args["interface"])

    result = engine.check_intent("daily", [("wire-test", "fortinet", {
        "lag": [{"name": name, "active_members": ["a", "b"]}],
    })], read)
    assert result["status"] == "pass" and result["checks"][0]["actual"] == ["a", "b"]
    assert sent == ["get system status", f"diagnose netlink aggregate name {name} show"]
