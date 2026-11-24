"""NX-OS VXLAN and EVPN reads through the proxy, MCP tool and fake SSH transport."""
from pathlib import Path

import pytest

import test_nxos_security_nxos_security
from test_nxos_security_nxos_security import PROFILE, nxos  # noqa: F401 - shared transport fixture


CAPTURES = Path(__file__).parent / "fixtures/real/cisco_nxos/nxos-overlay"
COMMANDS = {
    "nve_peers": "show nve peers",
    "nve_vni": "show nve vni",
    "nve_interface_detail": "show nve interface nve1 detail",
    "evpn_bgp_summary": "show bgp l2vpn evpn summary",
    "evpn_bgp_prefix": "show bgp l2vpn evpn {prefix}",
    "evpn_mac_ip": "show l2route evpn mac-ip all",
}


def capture(query, source="cisco"):
    return (CAPTURES / source / (query + ".out")).read_text()


def read(nxos, query, response, *, parameters=None, rc=0, **paging):
    invoke, calls = nxos
    parameters = parameters or {}
    command = COMMANDS[query].format_map(parameters)
    calls.clear()
    reply = invoke("ssh_read", {"platform": PROFILE, "query": query, "parameters": parameters, **paging},
                   enabled=[query], command=command, response=response, rc=rc)
    assert calls == ([] if paging.get("offset") else ["show version", command])
    return reply


@pytest.mark.parametrize(("query", "sample", "count", "first"), [
    ("nve_peers", "nve_peers", 1, {"peer_ip": "203.0.113.1", "state": "Up", "router_mac": "00:00:5e:00:53:01"}),
    ("nve_peers", "nve_peers_ipv6", 1, {"peer_ip": "2001:db8:1::1:1", "learn_type": "CP"}),
    ("nve_vni", "nve_vni", 3, {"vni": 900001, "vrf": "vxlan-900001", "bridge_domain": None}),
    ("nve_interface_detail", "nve_interface_detail", 1, {"interface": "nve1", "state": "Up", "encapsulation": "VXLAN"}),
    ("evpn_bgp_summary", "evpn_bgp_summary", 4, {"neighbor": "198.51.100.1", "state": "Idle(admin)", "vrf": "default"}),
    ("evpn_mac_ip", "evpn_mac_ip_compact", 2, {"topology_id": 101, "mac": "00:00:5e:00:53:04", "ip": "192.0.2.32",
                                              "producer": "BGP", "next_hops": "203.0.113.2"}),
    ("evpn_mac_ip", "evpn_mac_ip", 2, {"topology_id": 5, "ip": "192.0.2.131", "sequence": 0,
                                      "next_hops": "192.0.2.1 (Label: 2000005)"}),
])
def test_documented_overlay_output(nxos, query, sample, count, first):
    reply = read(nxos, query, capture(sample))
    data = reply["normalized"]
    assert reply["ok"] and reply["complete"] and reply["status"] == "ok", reply
    assert data["coverage"]["complete"] and not data["unparsed"]
    assert len(data["records"]) == count
    assert {key: data["records"][0][key] for key in first} == first
    if query == "nve_interface_detail":
        assert data["records"][0]["details"]["Source-Interface"] == "loopback1 (primary: 2001:db8:3:1::2)"
    elif query == "nve_vni":
        assert data["records"][1]["bridge_domain"] == "1001"
    elif query == "evpn_bgp_summary":
        assert data["records"][1]["prefixes"] == 476


def test_route_lookup_retains_both_rds_and_marks_published_partial_path(nxos):
    output = capture("evpn_bgp_prefix")
    params = {"prefix": "203.0.113.0"}
    reply = read(nxos, "evpn_bgp_prefix", output, parameters=params)
    assert reply["ok"] and not reply["complete"] and reply["status"] == "incomplete"
    first, second = reply["normalized"]["records"]
    assert first["rd"] == "198.51.100.14:115" and second["rd"] == "198.51.100.3:113"
    assert first["route_type"] == 5 and first["best_path"] == first["path_count"] == 1
    assert first["paths"][0]["next_hop"] == "198.51.100.9"
    assert "Ext[REDACTED]" in first["paths"][0]["attributes"]
    assert second["paths"][0]["next_hop"] == "198.51.100.9"

    # The contiguous first RD block from Cisco contains a complete path.
    first_rd = output.partition("Route Distinguisher: 198.51.100.3:113")[0]
    complete = read(nxos, "evpn_bgp_prefix", first_rd, parameters=params)
    assert complete["complete"] and complete["normalized"]["records"] == [first]


@pytest.mark.parametrize("query", COMMANDS)
def test_lab_without_overlay(nxos, query):
    params = {"prefix": "192.0.2.0"} if query == "evpn_bgp_prefix" else None
    empty = query == "evpn_mac_ip"
    reply = read(nxos, query, capture(query, "lab"), parameters=params, rc=0 if empty else 16)
    assert reply["ok"] is empty
    assert reply["complete"] is empty
    assert reply["status"] == ("empty" if empty else "unsupported")
    if empty:
        assert reply["normalized"]["records"] == []
    else:
        assert reply["error_code"] == "device_cli_error"


@pytest.mark.parametrize(("query", "sample", "retained"), [
    ("nve_peers", "nve_peers", 0),
    ("nve_vni", "nve_vni", 2),
    ("nve_interface_detail", "nve_interface_detail", 1),
    ("evpn_bgp_summary", "evpn_bgp_summary", 3),
    ("evpn_mac_ip", "evpn_mac_ip_compact", 1),
])
def test_cut_inside_required_fields_preserves_known_rows(nxos, query, sample, retained):
    lines = capture(sample).rstrip().splitlines()
    # Keep a fragment of the last record or detail field to model a cut.
    cut = "\n".join([*lines[:-1], lines[-1][:10]])
    reply = read(nxos, query, cut)
    assert reply["ok"] and not reply["complete"] and reply["status"] == "incomplete"
    data = reply["normalized"]
    assert not data["coverage"]["complete"] and data["unparsed"]
    assert len(data["records"]) == retained


def test_configured_bgp_peer_count_detects_whole_missing_row(nxos):
    output = capture("evpn_bgp_summary")
    cut = output.partition("198.51.100.11   4")[0]
    reply = read(nxos, "evpn_bgp_summary", cut)
    assert not reply["complete"] and reply["status"] == "incomplete"
    assert len(reply["normalized"]["records"]) == 3


def test_bgp_path_count_detects_whole_missing_path(nxos):
    output = capture("evpn_bgp_prefix").partition("Route Distinguisher: 198.51.100.3:113")[0]
    reply = read(nxos, "evpn_bgp_prefix", output.replace("1 available", "2 available"),
                 parameters={"prefix": "203.0.113.0"})
    assert not reply["complete"] and reply["status"] == "incomplete"
    assert len(reply["normalized"]["records"][0]["paths"]) == 1


def test_pager_retains_records_and_marks_capture_truncated(nxos):
    reply = read(nxos, "nve_peers", capture("nve_peers").rstrip() + "\n--More--")
    assert not reply["complete"] and reply["status"] == "truncated"
    assert len(reply["normalized"]["records"]) == 1


def test_output_pages_do_not_report_complete_records(nxos):
    query = "evpn_bgp_prefix"
    output = capture(query)
    params = {"prefix": "203.0.113.0"}
    first = read(nxos, query, output, parameters=params, max_bytes=1000)
    assert not first["complete"] and first["next_offset"] > 0
    assert "records" not in first["normalized"]
    tail = read(nxos, query, output, parameters=params, offset=first["next_offset"],
                content_sha256=first["content_sha256"])
    assert tail["pagination_source"] == "cached" and tail["next_offset"] is None
    assert not tail["complete"] and "records" not in tail["normalized"]


@pytest.mark.parametrize("query", COMMANDS)
@pytest.mark.parametrize("output", ["", " \r\n"])
def test_blank_overlay_capture_is_incomplete(nxos, query, output):
    params = {"prefix": "192.0.2.0"} if query == "evpn_bgp_prefix" else None
    reply = read(nxos, query, output, parameters=params)
    assert reply["status"] == "incomplete"
    assert reply["complete"] is False
    assert reply["normalized"]["coverage"]["complete"] is False
    assert reply["normalized"]["records"] == []


def test_blank_command_failure_is_a_transport_error(nxos):
    reply = read(nxos, "nve_peers", "", rc=16)
    assert reply["ok"] is False
    assert reply["complete"] is False
    assert reply["status"] == "transport_error"


@pytest.mark.parametrize("prefix", ["all", "192.0.2.0/24", "fe80::1%mgmt0", "192.0.2.0 | count"])
def test_prefix_rejects_non_address_selectors_before_transport(nxos, prefix):
    invoke, calls = nxos
    query = "evpn_bgp_prefix"
    reply = invoke("ssh_read", {"platform": PROFILE, "query": query, "parameters": {"prefix": prefix}}, enabled=[query])
    assert "error" in reply and not calls


def test_disabled_query_is_refused_before_transport(nxos):
    invoke, calls = nxos
    reply = invoke("ssh_read", {"platform": PROFILE, "query": "nve_vni"}, enabled=["nve_peers"])
    assert "error" in reply and not calls


def test_untested_firmware_warns_and_returns_records(nxos, monkeypatch):
    version = capture("identity", "lab").replace("9.3(12)", "10.3(5)")
    monkeypatch.setattr(test_nxos_security_nxos_security, "VERSION", version)
    reply = read(nxos, "evpn_mac_ip", capture("evpn_mac_ip"))
    assert reply["ok"] and reply["complete"] and len(reply["normalized"]["records"]) == 2
    assert reply["firmware_support"]["status"] == "untested"
    assert any(item["code"] == "firmware_untested" for item in reply["warnings"])
