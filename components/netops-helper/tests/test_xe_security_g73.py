"""IOS XE forwarding and security reads through the proxy and the MCP tool."""
import asyncio
from contextlib import nullcontext
import json
from pathlib import Path

from fastmcp import Client
import pytest

from netops_helper import engine, server
import test_proxy_contracts as policy


PROFILE = "cisco_xe"
FIXTURES = Path(__file__).parent / "fixtures"
LAB = FIXTURES / "real/cisco_xe/iolxe_17.18.2_g73"
DOCS = FIXTURES / "docs/cisco_xe/g73"
IOS_DOCS = FIXTURES / "docs/cisco_ios/g55"


@pytest.fixture
def xe(tmp_path, monkeypatch):
    proxy = policy._load_proxy()
    inventory, _, _, _ = policy._configure(proxy, tmp_path)
    calls = []
    output = {}

    def run_command(address, port, login, credential, key, command, **options):
        calls.append(command)
        rc, stdout, stderr = output[command]
        if stderr:
            assert options.get("separate_client_log")
        return engine.core_ssh.Result(rc=rc, stdout=stdout.encode(), stderr=stderr.encode(),
                                      said="", started_at="", finished_at="")

    monkeypatch.setattr(engine.core_ssh, "run_command", run_command)
    monkeypatch.setattr(engine, "_paced_connection", lambda *args: nullcontext())
    monkeypatch.setattr(engine, "host_key_line", lambda *args: "pinned-test-key")
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    async def public_call(request):
        async with Client(server.mcp) as client:
            return (await client.call_tool(request["name"], request["arguments"])).structured_content

    def invoke(query, command, fixture, *, table=None, parameters=None, filters=None, status_version="17.18.2",
               change=None, stderr="", rc=0, privileged=False, **paging):
        is_router = fixture.parent == LAB and fixture.name.startswith("router-")
        version_file = "router-version.out" if is_router else "l2-version.out"
        version = (LAB / version_file).read_text().replace("17.18.2", status_version)
        text = fixture.read_text()
        if change:
            text = change(text)
        output.clear()
        output.update({"show version": (0, version, ""), command: (rc, text, stderr)})
        calls.clear()
        interfaces = ["Ethernet0/0", "Ethernet0/1", "Ethernet0/2", "GigabitEthernet1/0/1", "TenGigabitEthernet1/0/23"]
        if query == "mac_table_interface":
            interfaces.append("Port-channel128")
        if query.startswith("ipv6_neighbors"):
            interfaces.append("Ethernet0/1.10")
        if query == "ip_interface_details":
            interfaces.append("Vlan99")
        section = policy._section()
        section.update(
            ssh_platform=PROFILE, enabled_queries=[query], device_types=["router" if is_router else "switch"],
            snmp_credential=None,
            read_inventory={"interfaces": interfaces, "vrfs": ["blue", "does-not-exist"]},
        )
        if privileged:
            section.update(account_role="admin-bounded", role_boundary="catalogue")
        section["egress"]["tcp_ports"].append(22)
        policy._write(inventory, policy._inventory(policy._device(section, PROFILE)))
        relay = proxy.Proxy()
        refusals = []
        relay._emit = refusals.append
        tool = "switch_read" if table else "ssh_read"
        args = {"table": table, **(filters or {})} if table else {
            "platform": PROFILE, "query": query, "parameters": parameters or {},
        }
        forwarded = relay.request(policy._request(73, tool, {"target": "device-a", **args, **paging}))
        if forwarded is None:
            return refusals[-1]
        return asyncio.run(public_call(json.loads(forwarded)["params"]))

    return invoke, calls


@pytest.mark.parametrize("fixture,table,query,command,filters,count,expected", [
    ("l2-mac_match", "mac_entry", "mac_table_address", "show mac address-table address 0000.5e00.5310",
     {"mac": "00:00:5e:00:53:10"}, 1, {"vlan_id": 99, "port": "Ethernet0/0"}),
    ("l2-mac_miss", "mac_entry", "mac_table_address", "show mac address-table address 0200.0000.0001",
     {"mac": "0200.0000.0001"}, 0, {}),
    ("l2-mac_port", "mac_entry", "mac_table_interface", "show mac address-table interface Ethernet0/0",
     {"interface": "Et0/0", "vlan_id": "99"}, 12, {"vlan_id": 99, "port": "Ethernet0/0"}),
    ("l2-mac_vlan", "mac_entry", "mac_table_vlan", "show mac address-table vlan 99",
     {"vlan_id": "99"}, 12, {"vlan_id": 99, "type": "dynamic"}),
    ("router-arp_global", "neighbor_l3", "arp_lookup", "show ip arp 198.51.100.1",
     {"ip": "198.51.100.1"}, 1, {"ip": "198.51.100.1", "interface": "Ethernet0/1.10"}),
    ("router-arp_vrf", "neighbor_l3", "arp_lookup_vrf", "show ip arp vrf blue 203.0.113.1",
     {"vrf": "blue", "ip": "203.0.113.1"}, 1, {"vrf": "blue", "mac": "00:00:5e:00:53:0e"}),
    ("router-arp_vrf_table", "neighbor_l3", "arp_table_vrf", "show ip arp vrf blue",
     {"vrf": "blue"}, 2, {"vrf": "blue", "interface": "Ethernet0/2"}),
    ("router-arp_absent", "neighbor_l3", "arp_lookup_vrf", "show ip arp vrf blue 203.0.113.254",
     {"vrf": "blue", "ip": "203.0.113.254"}, 0, {}),
    ("router-nd_port", "neighbor_l3", "ipv6_neighbors_interface", "show ipv6 neighbors Ethernet0/1.10",
     {"interface": "Ethernet0/1.10", "address_family": "ipv6"}, 1,
     {"ip": "2001:db8:1::1", "mac": "00:00:5e:00:53:0d", "interface": "Ethernet0/1.10"}),
    ("router-nd_vrf", "neighbor_l3", "ipv6_neighbors_vrf", "show ipv6 neighbors vrf blue",
     {"vrf": "blue", "address_family": "ipv6"}, 0, {}),
    ("router-nd_vrf_port", "neighbor_l3", "ipv6_neighbors_interface_vrf", "show ipv6 neighbors vrf blue Ethernet0/2",
     {"vrf": "blue", "interface": "Ethernet0/2"}, 0, {}),
    ("l2-snoop_binding", "dhcp_binding", "dhcp_snooping_binding", "show ip dhcp snooping binding",
     {}, 0, {}),
])
def test_switch_read_selects_the_enrolled_device_command(xe, fixture, table, query, command, filters, count, expected):
    call, calls = xe
    result = call(query, command, LAB / (fixture + ".out"), table=table, filters=filters)
    assert calls == ["show version", command], result
    assert result["status"] == ("ok" if count else "empty"), result
    assert result["coverage"]["complete"] and not result["unparsed"], result
    assert len(result["records"]) == count
    if count:
        assert expected.items() <= result["records"][0].items()
    assert result["firmware_support"]["status"] == "tested"


def test_missing_vrf_and_unenrolled_scope_are_distinct(xe):
    call, calls = xe
    query, command = "arp_lookup_vrf", "show ip arp vrf does-not-exist 203.0.113.254"
    result = call(query, command, LAB / "router-arp_vrf_invalid.out", table="neighbor_l3",
                  filters={"vrf": "does-not-exist", "ip": "203.0.113.254"})
    assert calls == ["show version", command]
    assert result["status"] == "not_applicable" and not result["coverage"]["complete"], result
    refused = call(query, command, LAB / "router-arp_vrf_invalid.out", table="neighbor_l3",
                   filters={"vrf": "other", "ip": "203.0.113.254"})
    assert not calls and refused.get("error"), refused


def test_an_unenrolled_switchport_is_refused_before_ssh(xe):
    call, calls = xe
    refused = call("mac_table_interface", "show mac address-table interface Ethernet0/5", LAB / "l2-mac_port.out",
                   table="mac_entry", filters={"interface": "Ethernet0/5"})
    assert not calls and refused.get("error"), refused


def test_privileged_diagnostics_stay_within_the_enrolled_query_scope(xe):
    call, calls = xe
    query = "dhcp_snooping_binding"
    command = "show ip dhcp snooping binding"
    result = call(query, command, LAB / "l2-snoop_binding.out", table="dhcp_binding", privileged=True)
    assert calls == ["show version", command] and result["status"] == "empty", result
    refused = call(query, command, LAB / "l2-snoop_binding.out", table="vlan", privileged=True)
    assert not calls and refused["error"]["data"]["field"] == "account_role", refused


@pytest.mark.parametrize("change", [
    lambda text: text.replace("criterion: 12", "criterion: 13"),
    lambda text: text + "Unexpected table line\n",
])
def test_mac_total_or_unknown_line_makes_results_incomplete(xe, change):
    call, _ = xe
    result = call("mac_table_interface", "show mac address-table interface Ethernet0/0", LAB / "l2-mac_port.out",
                  table="mac_entry", filters={"interface": "Ethernet0/0"}, change=change)
    assert result["status"] == "unparsed" and not result["coverage"]["complete"] and result["unparsed"], result


def test_populated_snooping_counts_and_filters(xe):
    call, _ = xe
    query, command = "dhcp_snooping_binding", "show ip dhcp snooping binding"
    result = call(query, command, DOCS / "snoop_binding.out", table="dhcp_binding", filters={"vlan_id": "10"})
    row, = result["records"]
    assert (row["interface"], row["vlan_id"], row["lease_seconds"]) == ("FortyGigabitEthernet1/0/2", 10, 85556)
    assert result["coverage"]["complete"]
    incomplete = call(query, command, DOCS / "snoop_binding.out", table="dhcp_binding",
                      change=lambda text: text.replace("bindings: 1", "bindings: 2"))
    assert incomplete["status"] == "unparsed" and not incomplete["coverage"]["complete"], incomplete


@pytest.mark.parametrize("query,command,fixture", [
    ("ipv4_access_lists", "show ip access-lists", "l2-acl4.out"),
    ("ipv6_access_lists", "show ipv6 access-list", "l2-acl6.out"),
])
def test_lab_acl_rules_are_structured(xe, query, command, fixture):
    call, _ = xe
    result = call(query, command, LAB / fixture)
    assert result["normalized"]["coverage"]["complete"], result
    acl = result["normalized"]["records"][0]
    rule, = acl["rules"]
    assert rule["sequence"] == 10 and rule["hits"] is None


def test_acl_counters_and_missing_values_with_untested_firmware(xe):
    call, calls = xe
    command = "show ipv6 access-list"
    result = call("ipv6_access_lists", command, DOCS / "acl6.out", status_version="17.18.99")
    acl, = result["normalized"]["records"]
    counted, uncounted = acl["rules"]
    assert calls == ["show version", command]
    assert result["status"] == "ok" and result["firmware_support"]["status"] == "untested"
    assert (counted["hits"], counted["sequence"], uncounted["hits"]) == (8, 10, None)


@pytest.mark.parametrize("query,command,parameters,fixture,marker", [
    ("ip_interface_details", "show ip interface Ethernet0/0", {"interface": "Ethernet0/0"},
     LAB / "l2-acl_port.out", "Inbound  access list is not set"),
    ("ip_interface_details", "show ip interface Vlan99", {"interface": "Vlan99"},
     LAB / "l2-acl_svi.out", "Outgoing access list is not set"),
    ("dhcp_snooping_status", "show ip dhcp snooping", {}, LAB / "l2-snoop.out", "Switch DHCP snooping is disabled"),
    ("dhcp_snooping_statistics", "show ip dhcp snooping statistics", {}, LAB / "l2-snoop_stats.out", "Packets Dropped"),
    ("port_security_interface", "show port-security interface Ethernet0/1", {"interface": "Ethernet0/1"},
     LAB / "l2-port_security.out", "Security Violation Count"),
    ("dhcp_server_statistics", "show ip dhcp server statistics", {}, LAB / "router-stats.out", "DHCPDISCOVER"),
    ("dhcp_server_bindings", "show ip dhcp binding", {}, DOCS / "lease.out", "Automatic"),
    ("dhcp_server_pools", "show ip dhcp pool", {}, DOCS / "pool.out", "Leased addresses"),
    ("dhcp_server_conflicts", "show ip dhcp conflict", {}, IOS_DOCS / "conflict.out", "Gratuitous ARP"),
    ("port_security_interface", "show port-security interface GigabitEthernet1/0/1",
     {"interface": "GigabitEthernet1/0/1"}, IOS_DOCS / "port_security.out", "Security Violation count"),
    ("port_security_addresses", "show port-security address", {}, IOS_DOCS / "secure_mac.out", "SecureConfigured"),
    ("dot1x_interface", "show dot1x interface GigabitEthernet1/0/1 details",
     {"interface": "GigabitEthernet1/0/1"}, DOCS / "dot1x.out", "AUTHENTICATOR"),
    ("arp_inspection_statistics", "show ip arp inspection statistics", {}, IOS_DOCS / "dai.out", "4618"),
    ("ip_source_guard", "show ip verify source", {}, DOCS / "source_guard.out", "active"),
])
def test_diagnostics_preserve_cli_evidence_but_report_a_pager(xe, query, command, parameters, fixture, marker):
    call, calls = xe
    result = call(query, command, fixture, parameters=parameters, privileged=True)
    assert calls == ["show version", command]
    assert result["ok"] and marker in result["untrusted_device_output"], result
    paged = call(query, command, fixture, parameters=parameters,
                 change=lambda text: "\n".join(text.splitlines()[:2]) + "\n--More--")
    assert paged["status"] == "truncated" and not paged["complete"], paged


@pytest.mark.parametrize("query,command,parameters,fixture", [
    ("dhcp_server_bindings", "show ip dhcp binding", {}, "router-lease"),
    ("dhcp_server_binding_address", "show ip dhcp binding 203.0.113.254", {"address": "203.0.113.254"}, "router-lease_address"),
    ("dhcp_server_pools", "show ip dhcp pool", {}, "router-pool"),
    ("dhcp_server_conflicts", "show ip dhcp conflict", {}, "router-conflict"),
    ("port_security_addresses", "show port-security address", {}, "l2-secure_mac"),
    ("arp_inspection_statistics", "show ip arp inspection statistics", {}, "l2-dai"),
    ("ip_source_guard", "show ip verify source", {}, "l2-source"),
])
def test_cli_absence_is_a_complete_empty_result(xe, query, command, parameters, fixture):
    call, calls = xe
    result = call(query, command, LAB / (fixture + ".out"), parameters=parameters)
    assert calls == ["show version", command]
    assert result["status"] == "empty" and result["ok"], result
    assert result["normalized"]["coverage"]["complete"] and not result["normalized"]["records"]


@pytest.mark.parametrize("query,command,fixture", [
    ("authentication_sessions_interface", "show access-session interface Ethernet0/1 details", "l2-auth"),
    ("dot1x_interface", "show dot1x interface Ethernet0/1 details", "l2-dot1x"),
    ("port_security_interface", "show port-security interface Ethernet0/1", "l2-ro_port_security"),
])
def test_lab_image_or_account_refusal_is_not_empty(xe, query, command, fixture):
    call, calls = xe
    result = call(query, command, LAB / (fixture + ".out"), parameters={"interface": "Ethernet0/1"})
    assert calls == ["show version", command]
    assert result["status"] == "permission_denied" and not result["ok"], result


def test_redirect_is_redacted_before_ssh_read_paging(xe):
    call, _ = xe
    query = "authentication_sessions_interface"
    interface = "TenGigabitEthernet1/0/23"
    result = call(query, f"show access-session interface {interface} details", DOCS / "access_session.out",
                  parameters={"interface": interface},
                  change=lambda text: text.replace(
                      "URL Redirect: <REDACTED>",
                      "URL \x1b[7mRedirect\x1b[0m: https://example.test/portal?token=z&sessionId=fake-session",
                  ))
    assert result["ok"], result
    assert "fake-session" not in json.dumps(result) and "token=z" not in json.dumps(result)
    output = result["untrusted_device_output"]
    assert "URL Redirect: <REDACTED>" in output and "URL Redirect ACL: web_acl" in output
    assert "mab           Authc Success" in output


def test_empty_read_with_unexpected_ssh_diagnostics_fails(xe):
    call, _ = xe
    result = call("dhcp_server_pools", "show ip dhcp pool", LAB / "router-pool.out", stderr="SSH channel failure\n")
    assert result["status"] == "unparsed" and result["error_code"] == "device_cli_error" and not result["ok"], result


@pytest.mark.parametrize("address,rc,expected", [
    ("192.0.2.10", 0, "empty"),
    ("192.0.2.10", 1, "unparsed"),
    ("192.0.2.99", 0, "unparsed"),
])
def test_empty_read_with_ssh_close_notice_requires_the_target_and_success(xe, address, rc, expected):
    call, _ = xe
    result = call("ip_source_guard", "show ip verify source", LAB / "l2-source.out", rc=rc,
                  stderr=f"Connection to {address} closed by remote host.\r\n")
    assert result["status"] == expected and result["ok"] == (expected == "empty"), result
