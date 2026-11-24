"""ROUTER-SECURITY public reads through the proxy and MCP with captured IOS output."""
import asyncio
from contextlib import nullcontext
import json
from pathlib import Path

import pytest

from netops_helper import engine, proxy, server
from test_proxy_contracts import _configure, _device, _inventory, _request, _section, _write

PROFILE = "cisco_ios"
FIXTURES = Path(__file__).parent / "fixtures"
REAL = FIXTURES / "real/cisco_ios"
LAB = REAL / "router-security"
DOCS = FIXTURES / "docs/cisco_ios/router-security"
VERSION = (REAL / "iosv_15.9.3M12_router_routing/version.out").read_text()


@pytest.fixture
def ios(tmp_path, monkeypatch):
    inventory, _, _, _ = _configure(proxy, tmp_path)
    calls, responses, refusals = [], {}, []

    def run_command(address, port, login, credential, key, command, *, suppress_login_banner=False, **options):
        calls.append(command)
        rc, stdout, stderr, banner = responses[command]
        if not suppress_login_banner:
            stderr = banner + stderr
        return engine.core_ssh.Result(rc=rc, stdout=stdout.encode(), stderr=stderr.encode(),
                                      said="", started_at="", finished_at="")

    monkeypatch.setattr(engine.core_ssh, "run_command", run_command)
    monkeypatch.setattr(engine, "_paced_connection", lambda *args: nullcontext())
    monkeypatch.setattr(engine, "host_key_line", lambda *args: "pinned-test-key")
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    def invoke(tool, arguments, *, enabled, command=None, text="", version=VERSION, stderr="", banner="",
               enrolled=()):
        responses.clear()
        responses.update({"show version": (0, version, "", ""), command: (0, text, stderr, banner)})
        calls.clear()
        interfaces = ["GigabitEthernet0/2", "GigabitEthernet1/0", "GigabitEthernet1/0/1", "GigabitEthernet3/0/2"]
        if "ipv6_neighbors_interface" in enabled or "ipv6_neighbors_interface_vrf" in enabled:
            interfaces.append("GigabitEthernet0/1.10")
        interfaces = list(dict.fromkeys([*interfaces, *enrolled]))
        section = dict(_section(), ssh_platform=PROFILE, enabled_queries=enabled, snmp_credential=None,
                       read_inventory={"vrfs": ["blue", "does-not-exist"], "interfaces": interfaces})
        section["egress"]["tcp_ports"].append(22)
        _write(inventory, _inventory(_device(section, PROFILE)))
        gateway = proxy.Proxy()
        gateway._emit = refusals.append
        forwarded = gateway.request(_request(55, tool, {"target": "device-a", **arguments}))
        if forwarded is None:
            return refusals[-1]
        request = json.loads(forwarded)["params"]
        result = asyncio.run(server.mcp.call_tool(request["name"], request["arguments"]))
        return result.structured_content

    return invoke, calls


@pytest.mark.parametrize("arguments,query,command,fixture,status,expected", [
    ({"table": "mac_entry", "mac": "0000.5e00.5305"},
     "mac_table_address", "show mac address-table address 0000.5e00.5305",
     "iosvl2-mac_match", "ok", {"vlan_id": 10, "port": "GigabitEthernet0/2"}),
    ({"table": "mac_entry", "mac": "0200.0000.0001"},
     "mac_table_address", "show mac address-table address 0200.0000.0001",
     "iosvl2-mac_miss", "empty", None),
    ({"table": "mac_entry", "interface": "GigabitEthernet0/2", "vlan_id": "20"},
     "mac_table_interface", "show mac address-table interface GigabitEthernet0/2",
     "iosvl2-mac_port", "ok", {"vlan_id": 20, "port": "GigabitEthernet0/2"}),
    ({"table": "mac_entry", "vlan_id": "10"},
     "mac_table_vlan", "show mac address-table vlan 10",
     "iosvl2-mac_vlan", "ok", {"vlan_id": 10}),
    ({"table": "neighbor_l3", "ip": "192.0.2.7", "vrf": "blue"},
     "arp_lookup_vrf", "show ip arp vrf blue 192.0.2.7",
     "iosv-arp", "ok", {"interface": "GigabitEthernet0/2", "vrf": "blue", "mac": "00:00:5e:00:53:01"}),
    ({"table": "neighbor_l3", "vrf": "blue"},
     "arp_table_vrf", "show ip arp vrf blue", "iosv-arp_vrf", "ok", {"vrf": "blue"}),
    ({"table": "neighbor_l3", "ip": "198.51.100.123", "vrf": "blue"},
     "arp_lookup_vrf", "show ip arp vrf blue 198.51.100.123",
     "iosv-arp_absent", "empty", None),
    ({"table": "neighbor_l3", "ip": "192.0.2.123"},
     "arp_lookup", "show ip arp 192.0.2.123", "iosv-arp_global", "empty", None),
    ({"table": "neighbor_l3", "interface": "GigabitEthernet0/1.10", "address_family": "ipv6"},
     "ipv6_neighbors_interface", "show ipv6 neighbors GigabitEthernet0/1.10",
     "iosv-nd_global", "ok", {"interface": "GigabitEthernet0/1.10", "mac": "00:00:5e:00:53:03"}),
    ({"table": "neighbor_l3", "vrf": "blue", "address_family": "ipv6"},
     "ipv6_neighbors_vrf", "show ipv6 neighbors vrf blue", "iosv-nd_vrf", "empty", None),
    ({"table": "neighbor_l3", "vrf": "blue", "interface": "GigabitEthernet0/2"},
     "ipv6_neighbors_interface_vrf", "show ipv6 neighbors vrf blue GigabitEthernet0/2",
     "iosv-nd_vrf_port", "empty", None),
    ({"table": "dhcp_binding"}, "dhcp_snooping_binding", "show ip dhcp snooping binding",
     "iosvl2-snoop_binding", "empty", None),
])
def test_switch_read_uses_scoped_cli(ios, arguments, query, command, fixture, status, expected):
    call, calls = ios
    reply = call("switch_read", arguments, enabled=[query], command=command,
                 text=(LAB / (fixture + ".out")).read_text())
    assert calls == ["show version", command], reply
    assert reply["status"] == status and reply["coverage"]["complete"], reply
    assert reply["firmware_support"]["status"] == "tested"
    if expected is None:
        assert reply["records"] == []
    else:
        assert reply["records"]
        assert all({key: row[key] for key in expected} == expected for row in reply["records"])


def test_snooping_binding_row_and_missing_summary(ios):
    call, calls = ios
    query, command = "dhcp_snooping_binding", "show ip dhcp snooping binding"
    arguments = {"table": "dhcp_binding", "interface": "Gi2/0/2", "vlan_id": "20"}
    text = (DOCS / "snoop_binding.out").read_text()
    reply = call("switch_read", arguments, enabled=[query], command=command, text=text)
    assert calls == ["show version", command]
    assert reply["status"] == "ok" and reply["coverage"]["complete"]
    row, = reply["records"]
    assert row["lease_seconds"] == 237 and row["interface"] == "GigabitEthernet2/0/2"
    reply = call("switch_read", arguments, enabled=[query], command=command,
                 text=text.split("Total number")[0])
    assert reply["status"] == "unparsed" and not reply["coverage"]["complete"]
    assert reply["records"] == [row]


@pytest.mark.parametrize("interface,short", [("Port-channel1", "Po1"), ("Port-channel64", "Po64"),
                                             ("TenGigabitEthernet1/0/1", "Te1/0/1")])
def test_mac_table_accepts_ios_switchport(ios, interface, short):
    call, calls = ios
    query, command = "mac_table_interface", f"show mac address-table interface {interface}"
    text = (LAB / "iosvl2-mac_port.out").read_text().replace("Gi0/2", short)
    reply = call("switch_read", {"table": "mac_entry", "interface": interface}, enabled=[query],
                 command=command, text=text, enrolled=[short])
    assert calls == ["show version", command], reply
    assert reply["status"] == "ok" and reply["coverage"]["complete"], reply
    assert len(reply["records"]) == 7
    assert {row["port"] for row in reply["records"]} == {interface}


def test_port_security_accepts_fastethernet(ios):
    call, calls = ios
    query, command = "port_security_interface", "show port-security interface FastEthernet0/1"
    text = (LAB / "iosvl2-port_security.out").read_text()
    reply = call("ssh_read", {"platform": PROFILE, "query": query, "parameters": {"interface": "FastEthernet0/1"}},
                 enabled=[query], command=command, text=text, enrolled=["Fa0/1"])
    assert calls == ["show version", command], reply
    assert reply["ok"] and reply["complete"] and "Security Violation Count" in reply["untrusted_device_output"], reply


@pytest.mark.parametrize("interface", ["Port-channel1|include", "TenGigabitEthernet1/0/1;", "Vlan10"])
def test_mac_table_rejects_invalid_switchport_even_if_listed(ios, interface):
    call, calls = ios
    reply = call("switch_read", {"table": "mac_entry", "interface": interface},
                 enabled=["mac_table_interface"], enrolled=[interface])
    assert reply.get("error") and not calls, reply


def test_empty_secure_mac_requires_header_and_zero_summary(ios):
    call, calls = ios
    query, command = "port_security_addresses", "show port-security address"
    arguments = {"platform": PROFILE, "query": query}
    text = (LAB / "iosvl2-secure_mac.out").read_text()
    reply = call("ssh_read", arguments, enabled=[query], command=command, text=text)
    assert calls == ["show version", command]
    assert reply["status"] == "empty" and reply["complete"], reply
    assert reply["normalized"]["coverage"]["complete"] and reply["normalized"]["records"] == []

    header, summary = text.split("Total Addresses", 1)
    for invalid in (header, header + "Total Addresses" + summary.replace(": 0", ": 1"),
                    text.replace("Vlan", "Unknown"), text + "unexpected\n"):
        reply = call("ssh_read", arguments, enabled=[query], command=command, text=invalid)
        assert reply["status"] != "empty", reply


@pytest.mark.parametrize("interface,displayed", [("GigabitEthernet0/1.10", "Gi0/1.10"), ("Vlan10", "Vlan10")])
def test_ipv6_neighbors_keeps_incomplete_ios_entry(ios, interface, displayed):
    call, calls = ios
    query, command = "ipv6_neighbors_interface", f"show ipv6 neighbors {interface}"
    text = (LAB / "iosv-nd_global.out").read_text().replace("0000.5e00.5303  REACH Gi0/1.10", f"-              INCMP {displayed}")
    arguments = {"table": "neighbor_l3", "interface": interface, "address_family": "ipv6"}
    reply = call("switch_read", arguments, enabled=[query], command=command, text=text, enrolled=[interface])
    assert calls == ["show version", command], reply
    assert reply["status"] == "ok" and reply["coverage"]["complete"] and not reply["unparsed"], reply
    row, = reply["records"]
    assert (row["ip"], row["interface"], row["mac"], row["state"]) == ("2001:db8:1::7", interface, None, "INCMP")

    reply = call("switch_read", arguments, enabled=[query], command=command, text=text.replace("INCMP", "REACH"),
                 enrolled=[interface])
    assert reply["status"] == "unparsed" and not reply["coverage"]["complete"] and not reply["records"], reply


def test_wrong_device_selector_does_not_look_empty_or_complete(ios):
    call, _ = ios
    reply = call("switch_read", {"table": "mac_entry", "mac": "0200.0000.0001"},
                 enabled=["mac_table_address"], command="show mac address-table address 0200.0000.0001",
                 text=(LAB / "iosvl2-mac_match.out").read_text())
    assert reply["status"] == "unparsed" and not reply["coverage"]["complete"]
    assert not reply["records"] and reply["unparsed"]


@pytest.mark.parametrize("query,command,fixture,first_hits,sequence", [
    ("ipv4_access_lists", "show ip access-lists", "acl4", 9, 50),
    ("ipv6_access_lists", "show ipv6 access-list", "acl6", 8, 10),
])
def test_acl_counts_preserve_missing_counters(ios, query, command, fixture, first_hits, sequence):
    call, calls = ios
    text = (DOCS / (fixture + ".out")).read_text()
    args = {"platform": PROFILE, "query": query}
    reply = call("ssh_read", args, enabled=[query], command=command, text=text)
    assert calls == ["show version", command]
    acl, = reply["normalized"]["records"]
    assert reply["status"] == "ok" and reply["normalized"]["coverage"]["complete"]
    assert acl["rules"][0]["hits"] == first_hits and acl["rules"][0]["sequence"] == sequence
    if query == "ipv6_access_lists":
        assert acl["rules"][-1]["hits"] is None
    reply = call("ssh_read", args, enabled=[query], command=command, text=text + "\n    invalid rule syntax\n")
    assert reply["status"] == "unparsed" and not reply["complete"]


@pytest.mark.parametrize("query,command,parameters,fixture,marker", [
    ("ip_interface_details", "show ip interface GigabitEthernet0/2", {"interface": "GigabitEthernet0/2"},
     LAB / "iosv-acl_port.out", "Inbound  access list is not set"),
    ("dhcp_server_binding_address", "show ip dhcp binding 192.0.2.2", {"address": "192.0.2.2"},
     DOCS / "lease.out", "Automatic"),
    ("dhcp_server_bindings", "show ip dhcp binding", {}, LAB / "iosv-lease.out", "Lease expiration"),
    ("dhcp_server_pools", "show ip dhcp pool", {}, DOCS / "pool.out", "Leased addresses"),
    ("dhcp_server_conflicts", "show ip dhcp conflict", {}, DOCS / "conflict.out", "Gratuitous ARP"),
    ("dhcp_server_statistics", "show ip dhcp server statistics", {}, LAB / "iosv-server_stats.out", "DHCPDISCOVER"),
    ("dhcp_snooping_status", "show ip dhcp snooping", {}, DOCS / "snoop.out", "snooping is enabled"),
    ("dhcp_snooping_statistics", "show ip dhcp snooping statistics", {}, DOCS / "snoop_stats.out", "Packets Dropped"),
    ("port_security_interface", "show port-security interface GigabitEthernet1/0/1", {"interface": "GigabitEthernet1/0/1"},
     DOCS / "port_security.out", "Violation count"),
    ("port_security_addresses", "show port-security address", {}, DOCS / "secure_mac.out", "SecureConfigured"),
    ("authentication_sessions_interface", "show authentication sessions interface GigabitEthernet3/0/2 details",
     {"interface": "GigabitEthernet3/0/2"}, DOCS / "auth.out", "Authc Failed"),
    ("dot1x_interface", "show dot1x interface GigabitEthernet1/0/1 details",
     {"interface": "GigabitEthernet1/0/1"}, DOCS / "dot1x.out", "Port Status = AUTHORIZED"),
    ("dot1x_interface", "show dot1x interface GigabitEthernet1/0 details",
     {"interface": "GigabitEthernet1/0"}, LAB / "iosvl2-dot1x.out", None),
    ("arp_inspection_statistics", "show ip arp inspection statistics", {}, DOCS / "dai.out", "4618"),
    ("ip_source_guard", "show ip verify source", {}, DOCS / "source.out", "deny-all"),
])
def test_diagnostic_show_keeps_the_cli_evidence(ios, query, command, parameters, fixture, marker):
    call, calls = ios
    args = {"platform": PROFILE, "query": query, "parameters": parameters}
    text = fixture.read_text()
    reply = call("ssh_read", args, enabled=[query], command=command, text=text)
    assert calls == ["show version", command], reply
    assert reply["ok"], reply
    if marker is not None:
        assert marker in reply["untrusted_device_output"]
        cutoff = text.splitlines()[:max(1, len(text.splitlines()) // 2)]
        reply = call("ssh_read", args, enabled=[query], command=command,
                     text="\n".join(cutoff) + "\n--More--")
        assert reply["status"] == "truncated" and not reply["complete"]
    else:
        assert reply["status"] == "empty"


def test_ios_refusal_and_empty_binding_are_distinct(ios):
    call, _ = ios
    denied = call("ssh_read", {"platform": PROFILE, "query": "port_security_interface",
                               "parameters": {"interface": "GigabitEthernet1/0"}},
                  enabled=["port_security_interface"], command="show port-security interface GigabitEthernet1/0",
                  text=(LAB / "iosvl2-ro_port_security.out").read_text())
    assert denied["status"] == "permission_denied" and not denied["ok"], denied
    text = (LAB / "iosv-lease_ip.out").read_text()
    absent = call("ssh_read", {"platform": PROFILE, "query": "dhcp_server_binding_address",
                               "parameters": {"address": "198.51.100.123"}},
                  enabled=["dhcp_server_binding_address"], command="show ip dhcp binding 198.51.100.123", text=text)
    assert absent["status"] == "empty" and absent["normalized"]["coverage"]["complete"], absent


def test_missing_vrf_is_distinct_from_empty_arp(ios):
    call, calls = ios
    query = "arp_lookup_vrf"
    command = "show ip arp vrf does-not-exist 192.0.2.123"
    reply = call("switch_read", {"table": "neighbor_l3", "vrf": "does-not-exist", "ip": "192.0.2.123"},
                 enabled=[query], command=command, text=(LAB / "iosv-arp_vrf_invalid.out").read_text())
    assert calls == ["show version", command]
    assert reply["status"] == "not_applicable" and not reply["records"] and not reply["coverage"]["complete"]


@pytest.mark.parametrize("arguments,query", [
    ({"table": "mac_entry", "interface": "GigabitEthernet0/9"}, "mac_table_interface"),
    ({"table": "neighbor_l3", "ip": "192.0.2.7", "vrf": "outside-inventory"}, "arp_lookup_vrf"),
    ({"table": "neighbor_l3", "interface": "GigabitEthernet0/9", "address_family": "ipv6"}, "ipv6_neighbors_interface"),
])
def test_scoped_parameters_are_authorized_before_transport(ios, arguments, query):
    call, calls = ios
    reply = call("switch_read", arguments, enabled=[query])
    assert reply.get("error") and not calls, reply


def test_untested_ios_warns_but_reads(ios):
    call, calls = ios
    query, command = "ipv4_access_lists", "show ip access-lists"
    reply = call("ssh_read", {"platform": PROFILE, "query": query}, enabled=[query], command=command,
                 text=(DOCS / "acl4.out").read_text(), version=VERSION.replace("15.9(3)M12", "15.9(3)M99"))
    assert calls == ["show version", command]
    assert reply["status"] == "ok" and reply["firmware_support"]["status"] == "untested"
    assert any(entry["code"] == "firmware_untested" for entry in reply["warnings"])



@pytest.mark.parametrize("tool,query,command,arguments,fixture", [
    ("ssh_read", "dhcp_server_pools", "show ip dhcp pool",
     {"platform": PROFILE, "query": "dhcp_server_pools"}, "iosv-pool"),
    ("switch_read", "arp_lookup", "show ip arp 192.0.2.123",
     {"table": "neighbor_l3", "ip": "192.0.2.123"}, "iosv-arp_global"),
])
def test_ios_login_banner_is_distinct_from_ssh_errors(ios, tool, query, command, arguments, fixture):
    call, calls = ios
    text = (LAB / (fixture + ".out")).read_text()
    banner = "\r\nAuthorized network operators only.\r\n"
    reply = call(tool, arguments, enabled=[query], command=command, text=text, banner=banner)
    assert calls == ["show version", command]
    assert reply["status"] == "empty", reply
    assert "Authorized network operators" not in json.dumps(reply)
    failed = call(tool, arguments, enabled=[query], command=command, text=text,
                  banner=banner, stderr="Unexpected SSH channel failure\r\n")
    assert failed["status"] == "unparsed" and failed["error_code"] == "device_cli_error", failed
