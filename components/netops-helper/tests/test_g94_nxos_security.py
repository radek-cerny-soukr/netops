"""Read paths for NX-OS ACLs and first-hop security against Cisco and lab output."""
from pathlib import Path
import asyncio
import json

import pytest

from netops_helper import engine, proxy, server
from test_proxy_contracts import _configure, _device, _inventory, _request, _section, _write


PROFILE = "cisco_nxos"
FIXTURES = Path(__file__).parent / "fixtures"
CAPTURES = FIXTURES / "real/cisco_nxos/g94_nexus9300v_9.3.12"
VERSION = (FIXTURES / "identity/cisco_nxos.txt").read_text()


def capture(name):
    return (CAPTURES / f"{name}.out").read_text()


@pytest.fixture
def nxos(tmp_path, monkeypatch):
    inventory, _, _, _ = _configure(proxy, tmp_path)
    responses, calls, refused = {}, [], []

    def exec_command(auth, address, known_hosts_line, credential, command, profile):
        assert profile == PROFILE
        calls.append(command)
        rc, stdout, stderr = (0, VERSION, "") if command == "show version" else responses[command]
        return engine.core_ssh.Result(rc=rc, stdout=stdout.encode(), stderr=stderr.encode(),
                                      said="", started_at="", finished_at="")

    monkeypatch.setattr(engine, "_exec_command", exec_command)
    monkeypatch.setattr(engine, "host_key_line", lambda *args: "pinned-test-key")
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    def invoke(tool, arguments, *, enabled, response=None, command=None, rc=0, stderr=""):
        if response is not None:
            responses[command] = rc, response, stderr
        section = dict(_section(), ssh_platform=PROFILE, enabled_queries=enabled, snmp_credential=None,
                       read_inventory={"vrfs": ["default", "management"], "interfaces": ["Vlan20", "Ethernet1/2"]})
        section["egress"]["tcp_ports"].append(22)
        _write(inventory, _inventory(_device(section, PROFILE)))
        gateway = proxy.Proxy()
        gateway._emit = refused.append
        forwarded = gateway.request(_request(94, tool, {"target": "device-a", **arguments}))
        if forwarded is None:
            return refused[-1]
        request = json.loads(forwarded)["params"]
        result = asyncio.run(server.mcp.call_tool(request["name"], request["arguments"]))
        return result.structured_content

    return invoke, calls


@pytest.mark.parametrize("arguments,query,command,fixture,status,expected", [
    ({"table": "mac_entry", "mac": "0000.5e00.5301", "vlan_id": "20"},
     "mac_table_address", "show mac address-table address 00:00:5e:00:53:01", "mac_colon", "ok", {"port": "Ethernet1/2"}),
    ({"table": "mac_entry", "mac": "0000.5e00.53ff"},
     "mac_table_address", "show mac address-table address 00:00:5e:00:53:ff", "mac_absent", "empty", None),
    ({"table": "neighbor_l3", "ip": "198.51.100.101", "vrf": "default", "vlan_id": "20"},
     "arp_lookup_vrf", "show ip arp 198.51.100.101 vrf default", "arp", "ok", {"vrf": "default", "interface": "Vlan20"}),
    ({"table": "neighbor_l3", "ip": "192.0.2.254", "vrf": "default"},
     "arp_lookup_vrf", "show ip arp 192.0.2.254 vrf default", "arp_absent", "empty", None),
    ({"table": "neighbor_l3", "vrf": "management"},
     "arp_table_vrf", "show ip arp vrf management", "arp_vrf", "ok", {"vrf": "management", "interface": "mgmt0"}),
    ({"table": "neighbor_l3", "ip": "2001:db8::1", "vrf": "management", "address_family": "ipv6"},
     "ipv6_neighbor_lookup_vrf", "show ipv6 neighbor 2001:db8::1 vrf management", "nd_vrf", "empty", None),
    ({"table": "neighbor_l3", "ip": "fe80::10"},
     "ipv6_neighbor_lookup", "show ipv6 neighbor fe80::10", "nd_wrapped", "ok", {"ip": "fe80::10", "vrf": "default"}),
    ({"table": "dhcp_binding", "ip": "203.0.113.254", "mac": "0000.5e00.5303", "interface": "Eth1/4", "vlan_id": "1"},
     "dhcp_snooping_binding", "show ip dhcp snooping binding", "bindings_populated", "ok", {"lease_seconds": 4995}),
    ({"table": "dhcp_binding", "ip": "203.0.113.254", "mac": "0000.5e00.5303", "interface": "Eth1/5"},
     "dhcp_snooping_binding", "show ip dhcp snooping binding", "bindings_populated", "ok", None),
    ({"table": "dhcp_binding"}, "dhcp_snooping_binding", "show ip dhcp snooping binding", "bindings", "empty", None),
])
def test_targeted_and_binding_tables(nxos, arguments, query, command, fixture, status, expected):
    invoke, calls = nxos
    reply = invoke("switch_read", arguments, enabled=[query], command=command, response=capture(fixture))
    assert calls == ["show version", command]
    assert reply["status"] == status and reply["coverage"]["complete"], reply
    if expected is None:
        assert reply["records"] == []
    else:
        row, = reply["records"]
        assert {key: row[key] for key in expected} == expected


def ssh(nxos, query, command, fixture, parameters=None, *, rc=0, output=None, stderr=""):
    invoke, calls = nxos
    reply = invoke("ssh_read", {"platform": PROFILE, "query": query, "parameters": parameters or {}},
                   enabled=[query], response=capture(fixture) if output is None else output, command=command, rc=rc,
                   stderr=stderr)
    assert calls == ["show version", command]
    return reply


def test_static_binding_with_infinite_lease(nxos):
    invoke, calls = nxos
    command = "show ip dhcp snooping binding"
    reply = invoke("switch_read", {
        "table": "dhcp_binding", "ip": "192.0.2.12", "mac": "0000.5e00.5301", "interface": "Eth2/46", "vlan_id": "13",
    }, enabled=["dhcp_snooping_binding"], command=command, response=capture("bindings_static"))
    assert calls == ["show version", command]
    assert reply["ok"] and reply["status"] == "ok" and reply["coverage"]["complete"]
    assert reply["records"] == [{
        "mac": "00:00:5e:00:53:01", "ip": "192.0.2.12", "type": "static", "vlan_id": 13,
        "lease_seconds": None, "static": True, "interface": "Ethernet2/46",
    }]


@pytest.mark.parametrize("tool", ["switch_read", "ssh_read"])
def test_targeted_mac_vlan_retains_vxlan_peer(nxos, tool):
    query, command = "mac_table_vlan", "show mac address-table vlan 10"
    if tool == "switch_read":
        invoke, calls = nxos
        reply = invoke(tool, {"table": "mac_entry", "vlan_id": "10"},
                       enabled=[query], command=command, response=capture("mac_vxlan_vlan"))
        assert calls == ["show version", command]
    else:
        reply = ssh(nxos, query, command, "mac_vxlan_vlan", {"vlan_id": "10"})["normalized"]
    assert reply["status"] == "ok" and reply["coverage"]["complete"]
    rows = {row["port"]: row for row in reply["records"]}
    assert rows.keys() == {"Ethernet1/54", "nve1", "vPC Peer-Link"}
    assert rows["nve1"] == {
        "mac": "00:00:5e:00:53:0b", "vlan_id": 10, "port": "nve1", "type": "dynamic", "vlan_name": None,
        "remote": True, "peer_ip": "192.0.2.33",
    }


def test_relay_pager_marks_raw_diagnostic_incomplete(nxos):
    partial = "\n".join(capture("relay_stats").splitlines()[:6]) + "\n--More--"
    reply = ssh(nxos, "dhcp_relay_statistics", "show ip dhcp relay statistics", "relay_stats", output=partial)
    assert reply["status"] == "truncated" and reply["next_offset"] is None
    assert reply["complete"] is False and reply["normalized"]["coverage"]["complete"] is False


@pytest.mark.parametrize("stderr,expected", [
    ("% Authorization failed\n", "permission_denied"),
    ("% Permission denied\n", "permission_denied"),
    ("% Invalid command\n", "unsupported"),
    (capture("dai_unsupported"), "unsupported"),
], ids=["authorization", "permission", "invalid-command", "lab-syntax"])
def test_nxos_empty_allowed_refuses_stderr_only_errors(nxos, stderr, expected):
    reply = ssh(nxos, "arp_inspection_statistics_vlan", "show ip arp inspection statistics vlan 20",
                "dai_vlan", {"vlan_id": "20"}, stderr=stderr)
    assert not reply["ok"] and reply["status"] == expected
    assert not reply["normalized"]["coverage"]["complete"]


@pytest.mark.parametrize("stderr", [
    "\r\nUser Access Verification\r\n",
    "Authorized access only.\r\n",
], ids=["default-banner", "custom-motd"])
def test_nxos_login_banner_allows_empty_dai_output(nxos, stderr):
    reply = ssh(nxos, "arp_inspection_statistics_vlan", "show ip arp inspection statistics vlan 20",
                "dai_vlan", {"vlan_id": "20"}, stderr=stderr)
    assert reply["ok"] and reply["status"] == "empty"
    assert reply["normalized"]["coverage"]["complete"] and reply["normalized"]["records"] == []


@pytest.mark.parametrize("query,command,fixture,parameters,family", [
    ("ipv4_access_lists", "show ip access-lists copp-system-p-acl-ssh", "acl_named", {"name": "copp-system-p-acl-ssh"}, "ipv4"),
    ("ipv6_access_lists", "show ipv6 access-lists copp-system-p-acl-ndp", "acl6_named", {"name": "copp-system-p-acl-ndp"}, "ipv6"),
    ("mac_access_lists", "show mac access-lists copp-system-p-acl-mac-lldp", "aclmac_named", {"name": "copp-system-p-acl-mac-lldp"}, "mac"),
])
def test_acl_rules_report_statistics_off(nxos, query, command, fixture, parameters, family):
    reply = ssh(nxos, query, command, fixture, parameters)
    assert reply["status"] == "ok" and reply["normalized"]["coverage"]["complete"]
    row, = reply["normalized"]["records"]
    assert row["family"] == family and row["statistics_enabled"] is False
    assert all(rule["hit_count"] is None for rule in row["entries"])


def test_acl_counters_preserve_an_explicit_zero(nxos):
    reply = ssh(nxos, "ipv4_access_lists", "show ip access-lists acl-2", "acl_hits", {"name": "acl-2"})
    row, = reply["normalized"]["records"]
    assert row["statistics_enabled"] is True
    assert [ace["hit_count"] for ace in row["entries"]] == [0, 3651331]


def test_acl_bindings_keep_configured_and_active_lists(nxos):
    reply = ssh(nxos, "ipv4_access_lists_summary", "show ip access-lists summary", "acl_port")
    row, = reply["normalized"]["records"]
    assert reply["normalized"]["coverage"]["complete"]
    assert row["total_entries"] == 2
    assert row["active_interfaces"] == row["configured_interfaces"] == [
        {"interface": "Ethernet1/49/1", "direction": "ingress", "type": "Port ACL"}
    ]


def test_acl_unknown_line_cannot_look_like_a_complete_list(nxos):
    reply = ssh(nxos, "ipv4_access_lists", "show ip access-lists copp-system-p-acl-ssh", "acl_named",
                {"name": "copp-system-p-acl-ssh"}, output=capture("acl_named") + "  30 permit\n")
    assert reply["status"] == "incomplete" and reply["complete"] is False
    assert reply["normalized"]["unparsed"]


@pytest.mark.parametrize("query,command,fixture,parameters,expected", [
    ("dhcp_snooping_status", "show ip dhcp snooping", "dhcp", {}, ("enabled", False)),
    ("dhcp_snooping_statistics", "show ip dhcp snooping statistics", "dhcp_stats", {},
     ("total", {"received": 0, "forwarded": 0, "dropped": 0})),
    ("dhcp_relay_status", "show ip dhcp relay", "relay", {}, ("helpers", [])),
    ("dhcp_relay_statistics", "show ip dhcp relay statistics", "relay_stats", {}, ("drop_reasons", {"Interface error": 2})),
    ("arp_inspection_statistics_vlan", "show ip arp inspection statistics vlan 1", "dai_counters", {"vlan_id": "1"},
     ("counters", {"ARP Req Dropped": 2, "DHCP Drops": 2})),
])
def test_first_hop_diagnostics(nxos, query, command, fixture, parameters, expected):
    reply = ssh(nxos, query, command, fixture, parameters)
    assert reply["normalized"]["coverage"]["complete"], reply
    row, = reply["normalized"]["records"]
    name, value = expected
    assert (value.items() <= row[name].items()) if isinstance(value, dict) else (row[name] == value)


@pytest.mark.parametrize("query,command,fixture,parameters", [
    ("dhcp_snooping_statistics", "show ip dhcp snooping statistics", "dhcp_stats", {}),
    ("dhcp_relay_statistics", "show ip dhcp relay statistics", "relay_stats", {}),
    ("arp_inspection_statistics_vlan", "show ip arp inspection statistics vlan 1", "dai_counters", {"vlan_id": "1"}),
])
def test_cut_counters_are_incomplete(nxos, query, command, fixture, parameters):
    reply = ssh(nxos, query, command, fixture, parameters, output="\n".join(capture(fixture).splitlines()[:12]))
    assert reply["status"] == "incomplete" and not reply["complete"]


@pytest.mark.parametrize("query,command,fixture,rc,expected,parameters", [
    ("ipv4_access_lists", "show ip access-lists G94-NOT-PRESENT", "acl_absent", 0, "empty", {"name": "G94-NOT-PRESENT"}),
    ("arp_inspection_statistics_vlan", "show ip arp inspection statistics vlan 20", "dai_vlan", 0, "empty", {"vlan_id": "20"}),
    ("arp_inspection_statistics_vlan", "show ip arp inspection statistics vlan 20", "dai_unsupported", 16, "unsupported", {"vlan_id": "20"}),
    ("dhcp_snooping_statistics", "show ip dhcp snooping statistics", "dhcp_unsupported", 16, "unsupported", {}),
])
def test_empty_and_refused_are_distinct(nxos, query, command, fixture, rc, expected, parameters):
    reply = ssh(nxos, query, command, fixture, parameters, rc=rc)
    assert reply["status"] == expected
    assert reply["ok"] is (rc == 0)


def test_neighbor_count_mismatch_preserves_available_rows(nxos):
    invoke, _ = nxos
    reply = invoke("switch_read", {"table": "neighbor_l3", "ip": "198.51.100.101", "vrf": "default"},
                   enabled=["arp_lookup_vrf"], command="show ip arp 198.51.100.101 vrf default",
                   response=capture("arp").replace("entries: 1", "entries: 2"))
    assert reply["status"] == "unparsed" and not reply["coverage"]["complete"]
    assert len(reply["records"]) == 1


@pytest.mark.parametrize("query,parameters", [
    ("arp_lookup_vrf", {"address": "192.0.2.1", "vrf": "not-enrolled"}),
    ("arp_lookup", {"address": "2001:db8::1"}),
    ("ipv4_access_lists", {"name": "summ"}),
    ("ip_interface_details", {"interface": "Ethernet1/7"}),
])
def test_scope_refusal_precedes_transport(nxos, query, parameters):
    invoke, calls = nxos
    reply = invoke("ssh_read", {"platform": PROFILE, "query": query, "parameters": parameters}, enabled=[query])
    assert "error" in reply and not calls
