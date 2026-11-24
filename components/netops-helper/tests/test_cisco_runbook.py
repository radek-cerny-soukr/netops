"""Public MCP scope, CLI transport, and sourced Cisco troubleshooting observations."""
import asyncio
import json
from pathlib import Path

import pytest

from netops_helper import engine, proxy, read_policy, server
from test_proxy_contracts import _configure, _device, _inventory, _request, _section, _write


FIXTURES = Path(__file__).parent / "fixtures/real"
IOS = "cisco_ios"
XE = "cisco_xe"


@pytest.fixture
def invoke(tmp_path, monkeypatch):
    inventory, _, _, _ = _configure(proxy, tmp_path)

    def call(tool, *, device="iosv", profile=IOS, updates=None, omit=(), change=None, vrfs=("blue",),
             rate_requests=None):
        router = device in {"iosv", "iol-xe-router"}
        directory = FIXTURES / profile / ("router-path" if profile == IOS else "xe-forwarding-path") / device
        if profile == IOS:
            interface = "GigabitEthernet0/2" if router else "GigabitEthernet1/0"
            ingress = "GigabitEthernet0/1.10" if router else "GigabitEthernet0/3"
            peer, source = "203.0.113.7", "198.51.100.7"
        else:
            interface = "Ethernet0/2" if router else "Ethernet1/0"
            ingress = "Ethernet0/1.10" if router else "Ethernet0/3"
            peer, source = "198.51.100.1", "203.0.113.1"
        address = "192.0.2.1"
        captures = {
            "version": ("show version", "version"),
            "interface_details": (f"show interfaces {interface}", "interface"),
            "stp_tree": ("show spanning-tree", "stp"),
            "route_lookup": (f"show ip route {address}", "rib"),
            "vrf_route_lookup": (f"show ip route vrf blue {peer}", "vrf_rib"),
            "vrf_arp_table": ("show arp vrf blue", "vrf_arp"),
            "ip_sla_statistics": ("show ip sla statistics", "sla"),
            "cef_lookup": (f"show ip cef {address} detail", "cef"),
            "ip_interface_details": (f"show ip interface {ingress}", "ip_interface"),
            "ip_policy": ("show ip policy", "policy"),
        }
        if profile == XE and router:
            captures.update(route_maps=("show route-map", "route_maps"),
                            ipv4_access_lists=("show ip access-lists", "acl"))
        args = {
            "triage_port": {"interface": interface},
            "triage_routing": {"address": address},
            "triage_flow": {"src": source, "dst": address, "port": 443, "proto": "tcp", "interface": ingress},
        }[tool]
        args.update(updates or {})
        vrf_ingress = tool == "triage_flow" and router and args["interface"] == interface
        if vrf_ingress:
            ingress_fixture = (FIXTURES / IOS / "router-security/iosv-acl_port.out"
                               if profile == IOS else directory / "vrf_ip_interface")
            captures["ip_interface_details"] = (f"show ip interface {interface}", ingress_fixture)
            captures["vrf_cef_lookup"] = (f"show ip cef vrf blue {peer} detail", "vrf_cef")
            captures["route_lookup"] = (f"show ip route {peer}", "rib")
            captures["cef_lookup"] = (f"show ip cef {peer} detail", "cef")
        commands = {command: label for command, label in captures.values()}
        if device == "iosvl2":
            commands[f"show interfaces {ingress}"] = "ingress_details"
        enrolled_interfaces = [interface] if vrf_ingress else [interface, ingress]
        if device == "iol-xe-switch":
            commands["show interfaces Ethernet2/0"] = "active_interface"
            enrolled_interfaces.append("Ethernet2/0")
        observed = []

        def exec_command(auth, address, known_hosts_line, credential, command, platform):
            assert platform == profile
            observed.append(command)
            label = commands[command]
            output = (directory / label).read_text()
            if command in {f"show ip route {peer}", f"show ip cef {peer} detail"}:
                # Place the existing global result in the selected destination's subnet.
                output = output.replace("192.0.2.0/24", peer.rsplit(".", 1)[0] + ".0/24")
            if change:
                output = change(label, output)
            return engine.core_ssh.Result(rc=0, stdout=output.encode(), stderr=b"",
                                          said="", started_at="", finished_at="")

        monkeypatch.setattr(engine, "_exec_command", exec_command)
        monkeypatch.setattr(engine, "host_key_line", lambda *args: "pinned-test-key")
        monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
        section = dict(_section(), ssh_platform=profile, snmp_credential=None,
                       enabled_queries=[query for query in captures
                                        if query not in omit and query in read_policy.READ_QUERIES[profile]],
                       read_inventory={"interfaces": enrolled_interfaces, "addresses": [address, peer, source],
                                       "vrfs": list(vrfs)})
        section["egress"]["tcp_ports"].append(22)
        if rate_requests is not None:
            section["rate_limit"] = {"requests": rate_requests, "window_seconds": 60}
        _write(inventory, _inventory(_device(section, profile)))
        gateway = proxy.Proxy()
        refused = []
        gateway._emit = refused.append
        forwarded = gateway.request(_request(59, tool, {"target": "device-a", **args}))
        if forwarded is None:
            return refused[-1], observed
        request = json.loads(forwarded)["params"]
        result = asyncio.run(server.mcp.call_tool(request["name"], request["arguments"]))
        return result.structured_content, observed

    return call


def evidence(result, check, status, query, excerpt):
    finding = result["findings"][check]
    assert finding["status"] == status, result
    assert any(line["line_number"] > 0 and line["query"] == query
               and excerpt in line["untrusted_device_output"] for line in finding["evidence"]), finding
    assert result["sources"][query]["content_sha256"]
    return finding


def test_rib_and_ip_sla_report_separate_sourced_observations(invoke):
    result, calls = invoke("triage_routing", updates={"sla_id": 69})
    assert result["ok"] and result["firmware_support"]["status"] == "tested", result
    assert evidence(result, "route", "route_observed", "route_lookup", "192.0.2.0/24")["table"] == "global"
    assert evidence(result, "ip_sla", "operation_observed", "ip_sla_statistics", "Timeout")["id"] == 69
    assert all(command.startswith("show ") for command in calls)


def test_vrf_route_and_arp_correlate_on_same_interface(invoke):
    result, _ = invoke("triage_routing", updates={"address": "203.0.113.7", "vrf": "blue"})
    assert evidence(result, "route", "route_observed", "vrf_route_lookup", "Routing Table: blue")["table"] == "blue"
    neighbor = evidence(result, "vrf_neighbor", "resolved", "vrf_arp_table", "203.0.113.7")
    assert neighbor["record"]["interface"] == "GigabitEthernet0/2"


@pytest.mark.parametrize(("interface", "status", "excerpt"), [
    ("GigabitEthernet1/0", "down", "administratively down"),
    ("GigabitEthernet0/3", "up", "line protocol is up"),
])
def test_switch_link_and_spanning_tree(invoke, interface, status, excerpt):
    result, _ = invoke("triage_port", device="iosvl2", updates={"interface": interface})
    evidence(result, "link", status, "interface_details", excerpt)
    if status == "up":
        stp = evidence(result, "spanning_tree", "state_observed", "stp_tree", "Gi0/3")
        assert {"instance": "VLAN0010", "state": "forwarding"} in stp["instances"]


def test_flow_reports_rib_and_cef_without_packet_disposition(invoke):
    result, _ = invoke("triage_flow")
    assert evidence(result, "route", "route_observed", "route_lookup", "192.0.2.0/24")["table"] == "global"
    assert evidence(result, "cef", "path_observed", "cef_lookup", "attached to GigabitEthernet0/1.10")["table"] == "global"
    evidence(result, "ingress_acl", "no_binding", "ip_interface_details", "access list is not set")
    assert result["packet_disposition"] == "unknown"


def test_missing_disabled_and_truncated_reads_leave_independent_source(invoke):
    def incomplete(label, text):
        return text.split("Route metric is")[0] if label == "rib" else text

    result, calls = invoke("triage_routing", updates={"sla_id": 69}, change=incomplete)
    assert result["verdict"] == "incomplete"
    assert result["findings"]["route"]["status"] == "unknown"
    evidence(result, "ip_sla", "operation_observed", "ip_sla_statistics", "Timeout")

    result, calls = invoke("triage_routing", updates={"sla_id": 69}, omit={"ip_sla_statistics"})
    assert result["findings"]["ip_sla"]["reason"] == "query_not_enabled"
    assert "show ip sla statistics" not in calls
    evidence(result, "route", "route_observed", "route_lookup", "192.0.2.0/24")

    def pager(label, text):
        return text + "\n --More--" if label == "cef" else text

    result, _ = invoke("triage_flow", change=pager)
    assert result["findings"]["cef"]["status"] == "unknown"


def test_cli_refusal_and_untested_firmware_do_not_erase_link(invoke):
    refusal = FIXTURES / IOS / "iosv_15.9.3M12_router_probes" / "unconfigured" / "ping_ipv6.out"

    def change(label, text):
        if label == "stp":
            return refusal.read_text()
        return text.replace("15.9(3)M12", "15.9(3)M13") if label == "version" else text

    result, _ = invoke("triage_port", change=change)
    evidence(result, "link", "up", "interface_details", "line protocol is up")
    assert result["findings"]["spanning_tree"]["status"] == "unknown"
    assert result["firmware_support"]["status"] == "untested"


@pytest.mark.parametrize(("tool", "update"), [
    ("triage_port", {"interface": "GigabitEthernet0/3"}),
    ("triage_routing", {"vrf": "outside"}),
    ("triage_routing", {"sla_id": True}),
    ("triage_flow", {"src": "192.0.2.20"}),
    ("triage_flow", {"interface": None}),
])
def test_refuses_out_of_scope_before_transport(invoke, tool, update):
    result, calls = invoke(tool, updates=update)
    assert "error" in result, result
    assert not calls


def test_xe_pbr_null0_and_cef_are_separate_observations(invoke):
    result, calls = invoke("triage_flow", device="iol-xe-router", profile=XE)
    assert result["ok"] and result["firmware_support"]["status"] == "tested", result
    route = evidence(result, "route", "route_observed", "route_lookup", "via Null0")
    assert route["records"][0]["protocol"] == "static"
    assert route["records"][0]["interface"] == "Null0"
    evidence(result, "cef", "discard_path_observed", "cef_lookup", "attached to Null0")
    evidence(result, "ip_policy", "binding_observed", "ip_policy", "Ethernet0/1.10 XE-ROUTING-PBR")
    policy = evidence(result, "route_map", "clauses_observed", "route_maps", "interface Null0")
    assert policy["clauses"][0]["sets_null0"] and policy["clauses"][0]["policy_matches"] > 0
    evidence(result, "access_lists", "definitions_observed", "ipv4_access_lists", "permit ip any 192.0.2.0")
    assert result["packet_disposition"] == "unknown"
    assert "show ip access-lists" in calls


def test_ios_routing_preserves_static_protocol_on_interface_only_next_hop(invoke):
    # Feed the measured XE-ROUTING detail format through the IOS engine's shared parser.
    capture = FIXTURES / XE / "xe-forwarding-path/iol-xe-router/rib"
    result, _ = invoke("triage_routing", change=lambda label, text: capture.read_text() if label == "rib" else text)
    route = evidence(result, "route", "route_observed", "route_lookup", "via Null0")
    assert route["records"][0]["protocol"] == "static"
    assert route["records"][0]["interface"] == "Null0"


@pytest.mark.parametrize(("profile", "device", "interface", "peer"), [
    (IOS, "iosv", "GigabitEthernet0/2", "203.0.113.7"),
    (XE, "iol-xe-router", "Ethernet0/2", "198.51.100.1"),
])
def test_cisco_flow_uses_ingress_vrf(invoke, profile, device, interface, peer):
    result, calls = invoke("triage_flow", device=device, profile=profile, updates={"interface": interface, "dst": peer})
    route = evidence(result, "route", "route_observed", "vrf_route_lookup", "Routing Table: blue")
    cef = evidence(result, "cef", "path_observed", "vrf_cef_lookup", f"attached to {interface}")
    assert route["table"] == cef["table"] == "blue"
    assert route["records"][0]["interface"] == interface
    assert calls.index(f"show ip interface {interface}") < calls.index(f"show ip route vrf blue {peer}")
    assert f"show ip cef vrf blue {peer} detail" in calls
    assert f"show ip route {peer}" not in calls and f"show ip cef {peer} detail" not in calls


def test_classic_ios_flow_reserves_only_one_routing_context(invoke):
    interface, peer = "GigabitEthernet0/2", "203.0.113.7"
    result, calls = invoke("triage_flow", updates={"interface": interface, "dst": peer}, rate_requests=5,
                           omit={"vrf_route_lookup", "cef_lookup", "ip_policy"})
    evidence(result, "cef", "path_observed", "vrf_cef_lookup", f"attached to {interface}")
    assert not any(command.startswith("show ip route ") for command in calls)


def test_classic_ios_flow_accepts_explicit_vrf_without_wccp(invoke):
    interface, peer = "GigabitEthernet0/2", "203.0.113.7"

    def without_wccp(label, output):
        if label == FIXTURES / IOS / "router-security/iosv-acl_port.out":
            return "\n".join(line for line in output.splitlines() if "IPv4 WCCP" not in line)
        return output

    result, _ = invoke("triage_flow", updates={"interface": interface, "dst": peer}, change=without_wccp)
    evidence(result, "route", "route_observed", "vrf_route_lookup", "Routing Table: blue")


@pytest.mark.parametrize("failure", ["disabled", "truncated", "malformed", "outside", "scoped_queries_disabled"])
def test_cisco_flow_never_falls_back_to_global(invoke, failure):
    peer, interface = "203.0.113.7", "GigabitEthernet0/2"
    omit = {"ip_interface_details"} if failure == "disabled" else set()
    if failure == "scoped_queries_disabled":
        omit = {"vrf_route_lookup", "vrf_cef_lookup"}

    def change(label, output):
        if label == FIXTURES / IOS / "router-security/iosv-acl_port.out":
            if failure == "truncated":
                return output.split('VPN Routing/Forwarding "blue"')[0]
            if failure == "malformed":
                return output.replace('VPN Routing/Forwarding "blue"', 'VPN Routing/Forwarding <unknown>')
        return output

    result, calls = invoke("triage_flow", updates={"interface": interface, "dst": peer}, omit=omit,
                           change=change, vrfs=() if failure == "outside" else ("blue",))
    assert result.get("verdict") == "incomplete", result
    assert result["findings"]["ip_policy"]["status"] == "no_binding"
    for check in ("route", "cef"):
        finding = result["findings"][check]
        assert finding["status"] == "unknown"
        assert finding["table"] == ("blue" if failure in {"outside", "scoped_queries_disabled"} else None)
    assert not any(command.startswith(("show ip route ", "show ip cef ")) for command in calls)


def test_xe_truncated_route_map_preserves_binding_and_cef(invoke):
    def truncate(label, output):
        return output.split("Policy routing matches:")[0] if label == "route_maps" else output

    result, calls = invoke("triage_flow", device="iol-xe-router", profile=XE, change=truncate)
    assert result["findings"]["route_map"]["status"] == "unknown"
    assert result["verdict"] == "incomplete"
    evidence(result, "ip_policy", "binding_observed", "ip_policy", "XE-ROUTING-PBR")
    evidence(result, "cef", "discard_path_observed", "cef_lookup", "attached to Null0")
    assert "show ip access-lists" not in calls


def test_xe_vrf_peer_and_switch_port_down(invoke):
    result, _ = invoke("triage_routing", device="iol-xe-router", profile=XE,
                       updates={"address": "198.51.100.1", "vrf": "blue"})
    assert evidence(result, "vrf_neighbor", "resolved", "vrf_arp_table", "198.51.100.1")[
        "record"]["interface"] == "Ethernet0/2"
    result, _ = invoke("triage_port", device="iol-xe-switch", profile=XE)
    evidence(result, "link", "down", "interface_details", "administratively down")
    result, _ = invoke("triage_port", device="iol-xe-switch", profile=XE, updates={"interface": "Ethernet2/0"})
    assert {"instance": "VLAN0001", "state": "forwarding"} in evidence(
        result, "spanning_tree", "state_observed", "stp_tree", "Et2/0")["instances"]


def test_xe_l2_ipv4_processing_disabled_cannot_establish_ingress_table(invoke):
    result, calls = invoke("triage_flow", device="iol-xe-switch", profile=XE)
    assert all(result["findings"][check]["status"] == "unknown" for check in ("route", "cef"))
    assert not any(command.startswith(("show ip route ", "show ip cef ")) for command in calls)
    evidence(result, "ingress_acl", "ipv4_processing_disabled", "ip_interface_details",
             "Internet protocol processing disabled")


def test_xe_wrong_port_family_is_refused_before_transport(invoke):
    response, calls = invoke("triage_port", device="iol-xe-router", profile=XE, updates={"interface": "Gi9/0; show clock"})
    assert "error" in response
    assert calls == []
