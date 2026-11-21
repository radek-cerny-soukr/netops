"""Exercise public MCP/proxy scope, engine reads, and interpretation of Nexus captures."""
import asyncio
import json
from pathlib import Path

import pytest

from netops_helper import engine, proxy, server
from test_proxy_contracts import _configure, _device, _inventory, _request, _section, _write


PROFILE = "cisco_nxos"
TOOL = "triage_nxos_path"
CAPTURES = Path(__file__).parent / "fixtures/real/cisco_nxos/g99_9.3.12"


@pytest.fixture
def nexus(tmp_path, monkeypatch):
    inventory, _, _, _ = _configure(proxy, tmp_path)
    calls = []

    def invoke(device="d-nxos", *, argument_updates=None, modify_rib=lambda text: text, omit=(), firmware=None,
               blank_source=None, accounting=None):
        port = "Ethernet1/2" if device == "d-nxos" else "Port-channel128"
        address = "203.0.113.1" if device == "d-nxos" else "192.0.2.99"
        responses = {
            "show version": ("version", 0, "version"),
            f"show interface {port}": ("port", 0, "interface_details"),
            f"show ip route {address}": ("rib", 0, "route_lookup"),
            f"show spanning-tree interface {port} detail": ("stp", 0, "stp_interface_detail"),
            f"show lldp neighbors interface {port} detail": ("lldp", 244 if device == "d-nxos" else 16, "lldp_neighbor_interface"),
            "show ip access-lists summary": ("acl", 0, "ipv4_access_lists_summary"),
            "show ip arp": ("arptable", 0, "arp_table"),
            "show forwarding ipv4 route": ("fib", 244, "forwarding_ipv4_route"),
            "show vpc brief": ("vpc", 0, "vpc_status"),
        }

        def exec_command(auth, address, known_hosts_line, credential, command, profile):
            assert profile == PROFILE
            calls.append(command)
            suffix, rc, query = responses[command]
            output = (CAPTURES / f"{device}-{suffix}").read_text()
            if query == blank_source:
                output, rc = "", 0
            if suffix == "rib":
                output = modify_rib(output)
            if suffix == "version" and firmware:
                output = output.replace("9.3(12)", firmware)
            return engine.core_ssh.Result(rc=rc, stdout=output.encode(), stderr=b"",
                                          said="", started_at="", finished_at="")

        monkeypatch.setattr(engine, "_exec_command", exec_command)
        monkeypatch.setattr(engine, "host_key_line", lambda *args: "pinned-test-key")
        monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

        section = dict(_section(), ssh_platform=PROFILE, snmp_credential=None,
                       enabled_queries=[query for _, _, query in responses.values() if query not in omit],
                       read_inventory={"interfaces": [port], "addresses": [address]},
                       rate_limit={"requests": 30, "window_seconds": 60})
        section["egress"]["tcp_ports"].append(22)
        _write(inventory, _inventory(_device(section, PROFILE)))
        gateway = proxy.Proxy()
        refused = []
        gateway._emit = refused.append
        forwarded = gateway.request(_request(99, TOOL, {
            "target": "device-a", "interface": port, "address": address, **(argument_updates or {}),
        }))
        if forwarded is None:
            return refused[-1]
        if accounting is not None:
            accounting.update(gateway._rate_status("device-a", section["rate_limit"], triage=True))
        request = json.loads(forwarded)["params"]
        return asyncio.run(server.mcp.call_tool(request["name"], request["arguments"])).structured_content

    return invoke, calls


def test_path_charges_the_identity_reads_to_the_triage_budget(nexus):
    invoke, calls = nexus
    accounting = {}
    invoke(accounting=accounting)
    assert calls.count("show version") > 1
    # One identity read plus two reads for each of the seven enrolled Ethernet diagnostics.
    assert accounting["used"] == 15


def test_correlates_local_port_route_and_arp_with_sources(nexus):
    invoke, calls = nexus
    result = invoke()
    assert result["verdict"] == "incomplete", result
    assert result["rib_status"] == "route_observed"
    findings = result["findings"]
    assert findings["interface_details"]["records"] == [{"port": "Ethernet1/2", "link_state": "up"}]
    assert findings.get("stp_interface_detail", {}).get("records", [{}])[0].get("state") == "forwarding", result
    route, = findings["route_lookup"]["records"]
    assert (route["prefix"], route["next_hop"], route["interface"]) == ("203.0.113.1/32", "198.51.100.1", "Vlan10")
    neighbor, = findings["arp_table"]["records"]
    assert (neighbor["ip"], neighbor["interface"]) == (route["next_hop"], route["interface"])
    assert result["sources"]["route_lookup"]["content_sha256"]
    assert "forwarding_ipv4_route" not in findings
    assert {"source": "forwarding_ipv4_route", "reason": "device_cli_error"} in result["missing"]
    assert result["firmware_support"]["status"] == "tested"
    assert "show vpc brief" not in calls


def test_local_vpc_and_explicit_no_route(nexus):
    invoke, calls = nexus
    result = invoke("b04-nx-a")
    assert result["rib_status"] == "route_not_found", result
    assert result["findings"]["route_lookup"]["records"] == []
    member, = result["findings"]["vpc_status"]["records"]
    assert member["id"] == 128 and member["consistency"] == "success", member
    assert result["verdict"] == "incomplete"
    assert "show ip arp" not in calls


@pytest.mark.parametrize(("device", "source"), [
    ("d-nxos", "version"),
    ("d-nxos", "interface_details"),
    ("d-nxos", "route_lookup"),
    ("d-nxos", "stp_interface_detail"),
    ("d-nxos", "lldp_neighbor_interface"),
    ("d-nxos", "forwarding_ipv4_route"),
    ("d-nxos", "ipv4_access_lists_summary"),
    ("d-nxos", "arp_table"),
    ("b04-nx-a", "vpc_status"),
])
def test_blank_source_is_missing_and_other_evidence_is_retained(nexus, device, source):
    invoke, _ = nexus
    result = invoke(device, blank_source=source)
    assert result["verdict"] == "incomplete"
    assert result["sources"][source]["status"] == "missing"
    assert {"source": source, "reason": "missing"} in result["missing"]
    assert source not in result["findings"]
    if source == "version":
        assert result["findings"] == {}
    elif source == "route_lookup":
        assert result["rib_status"] == "unknown"
        assert "interface_details" in result["findings"]
    else:
        assert result["rib_status"] == ("route_observed" if device == "d-nxos" else "route_not_found")
        assert "route_lookup" in result["findings"]


def test_missing_route_continuation_and_unenrolled_optional_read(nexus):
    invoke, calls = nexus
    result = invoke(modify_rib=lambda text: text.split("    *via")[0], omit=("forwarding_ipv4_route",),
                    firmware="9.3(13)")
    assert result["verdict"] == "incomplete" and result["rib_status"] == "unknown", result
    assert {"source": "route_lookup", "reason": "unparsed"} in result["missing"]
    assert {"source": "forwarding_ipv4_route", "reason": "query_not_enabled"} in result["missing"]
    assert "interface_details" in result["findings"]
    assert result["firmware_support"]["status"] == "untested"
    assert "show ip arp" not in calls and "show forwarding ipv4 route" not in calls


@pytest.mark.parametrize("argument_updates", [{"interface": "Ethernet1/48"}, {"address": "203.0.113.2"}])
def test_scope_rejected_before_transport(nexus, argument_updates):
    invoke, calls = nexus
    response = invoke(argument_updates=argument_updates)
    assert "error" in response, response
    assert calls == []
