"""FortiOS review regressions through the real Helper with a fake SSH transport."""
import json
from pathlib import Path

import pytest

from test_firewall_routing_fortigate_routing import FORTIGATE_HA, SIXTY, _fake, _read, _table

FIXTURES = Path(__file__).parent / "fixtures/real/fortinet/firewall_routing_20261118"
DOCS = json.loads((FIXTURES / "r2-docs.json").read_text())


@pytest.mark.parametrize("capture,port", [("rib_inactive", "port1"), ("rib_inactive_without_selected", "wan1")])
def test_explicit_inactive_path(monkeypatch, capture, port):
    _fake(monkeypatch, DOCS[capture])
    rib = _read("routing_table_database")["route_database"]
    assert rib["state"] == "ok"
    assert rib["inactive"][0]["interface"] == port
    assert rib["entries"][0]["interface"] == port
    if capture == "rib_inactive":
        assert [entry["interface"] for entry in rib["inactive"][0]["selected_instead"]] == ["port2"]


def test_ipv6_recursive_bgp_path_in_installed_table(monkeypatch):
    _fake(monkeypatch, DOCS["ipv6_recursive_table"])
    result = _table("route", ["ipv6_routing_table"], address_family="ipv6")
    assert result["coverage"]["complete"] is True
    assert result["records"] == [{"prefix": "2001:db8:1::/64", "next_hop": "2001:db8::2",
                                  "interface": "agg1", "protocol": "bgp", "vrf": "default"}]


def test_ipv6_recursive_bgp_path_in_database(monkeypatch):
    _fake(monkeypatch, DOCS["ipv6_recursive_rib"])
    rib = _read("ipv6_routing_table_database")["route_database"]
    assert rib["state"] == "ok"
    assert [(row["gateway"], row["interface"], row["fib"]) for row in rib["entries"]] == [
        ("2001:db8::2", "agg1", True)]


def test_fortios_ospf_parallel_neighbors(monkeypatch):
    _fake(monkeypatch, DOCS["ospf_neighbors"])
    result = _table("ospf_neighbor", ["ospf_neighbors"])
    assert result["coverage"]["complete"] is True
    assert [(row["interface"], row["state"], row["role"], row["vrf"]) for row in result["records"]] == [
        ("wan1", "full", "DR", "default"), ("wan2", "full", "DR", "default")]


def test_short_lacp_capture_is_incomplete(monkeypatch):
    _fake(monkeypatch, SIXTY["lacp_detail_fortilink"].split("member: b")[0])
    result = _table("lag", ["lacp_detail"], {"interfaces": ("fortilink",)}, interface="fortilink")
    assert result["coverage"]["complete"] is False
    assert result["records"][0]["members"] == [{"port": "a", "state": "bundled"}]


def test_short_bgp_neighbor_detail_is_incomplete(monkeypatch):
    body = FORTIGATE_HA["bgp_neighbors_peer"].split("  Last read", 1)[0]
    _fake(monkeypatch, body)
    result = _read("bgp_neighbor_detail")["bgp_neighbors"]
    assert result["state"] == "incomplete"
    assert result["neighbors"][0]["state"] == "Established"


def test_partial_fortios_error_counters_cannot_issue_baseline(monkeypatch):
    body = "\n".join(line for line in SIXTY["interface_details_wan1"].splitlines() if not line.startswith("stat:"))
    _fake(monkeypatch, body)
    result = _table("interface_errors", ["interface_details"], {"interfaces": ("wan1",)}, interface="wan1")
    assert result["coverage"]["complete"] is False
    assert result["counter_baseline"] is None
    assert result["records"][0]["crc"] == 0


LIVE = json.loads((FIXTURES / "r2-live.json").read_text())


def test_fortios_local_stp_port_states(monkeypatch):
    sent = _fake(monkeypatch, LIVE["60f"]["stp"])
    result = _table("stp_port", ["local_stp_ports"])
    assert sent[-1] == "get system stp list"
    assert result["coverage"]["complete"] is True
    assert [(row["instance"], row["port"], row["state"]) for row in result["records"]] == [
        ("internal", f"internal{index}", "down") for index in range(1, 6)]


def test_fortios_local_port_vlan_membership(monkeypatch):
    sent = _fake(monkeypatch, {
        "show system virtual-switch": LIVE["60f"]["virtual-switch"],
        "get system interface": LIVE["60f"]["switch-interfaces"],
    })
    result = _table("port_vlan", ["local_switch_vlans"])
    assert "show system virtual-switch" in sent and sent[-1] == "get system interface"
    assert result["coverage"]["complete"] is True
    assert [(row["port"], row["mode"], row["access_vlan"]) for row in result["records"]] == [
        (f"internal{index}", "access", None) for index in range(1, 6)]


def test_interface_list_reports_aggregate_vlan_and_tunnel_traffic(monkeypatch):
    from conftest import FORTIOS_STATUS
    from netops_helper import engine

    data = LIVE["60f"]
    outputs = {
        engine._IDENTITY_COMMAND: FORTIOS_STATUS,
        "diagnose netlink interface list": SIXTY["interface_list"],
        "diagnose netlink device list": data["netlink-device"],
        "diagnose netlink interface packet-rate": data["packet-rate"],
    }
    monkeypatch.setattr(engine, "read_from_device", lambda auth, platform, command: (0, outputs[command]))
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    indexed = {row["name"]: row for row in _read("interface_list", max_bytes=48_000)["interfaces"]["interfaces"]}
    assert [(indexed[name]["rx_bytes"], indexed[name]["tx_bytes"]) for name in
            ("fortilink", "PVE-MGMT", "l2t.root")] == [
                (5715881028, 11800875894), (5558104866, 11751088935), (0, 152)]
    assert indexed["fortilink"]["speed_bps"] == 1_000_000_000
    assert indexed["l2t.root"]["rx_bps"] == 0
