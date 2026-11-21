import dataclasses
from pathlib import Path

import pytest

from conftest import FORTIADC_STATUS, LOOPBACK, PORT, _fortinet_wire, _plain_query, _target
from netops_core.ssh import Result
import netops_helper.engine as engine
from netops_helper import triage_slb
from netops_helper.read_policy import READ_QUERIES


ADC_PROMPT = b"FortiADC-VM # "
SLB = "diagnose server-load-balance slb_load"
INVENTORY = {"vrfs": ("default",), "interfaces": ("port1", "Vlan10", "Ethernet2", "irb.20", "GigabitEthernet1/0", "Ethernet0/1"), "config_access": ("read",),
             "vlans": ("default",), "adc_virtual_servers": ("VS_APP_HTTP",), "routing_instances": ("g132",), "addresses": ("192.0.2.1",),
             "ipsec_tunnels": ("netops-g14",)}
LEGAL_EMPTY = {
    # G57: these four commands returned blank successful replies on IOSv and IOL XE.
    **{(profile, name): parameters for profile in ("cisco_ios", "cisco_xe") for name, parameters in (
        ("qos_policy", {"interface": "Vlan10"}), ("nat_translations", {}), ("nat_statistics", {}), ("ikev2_sa", {}),
    )},
    ("ruckus_unleashed", "access_points"): {},
    ("ruckus_unleashed", "l2_acls"): {},
    ("ruckus_unleashed", "mgmt_acls"): {},
    ("ruckus_unleashed", "l3_acls"): {},
    ("ruckus_unleashed", "aaa_servers"): {},
    ("ruckus_unleashed", "dhcp_relays"): {},
    ("ruckus_unleashed", "static_routes"): {},
    ("fortinet", "bgp_neighbor_detail"): {},
    ("fortinet", "ipv6_bgp_neighbor_detail"): {},
    ("fortinet", "local_stp_ports"): {},
    ("fortinet", "dhcp_leases_all"): {},
    ("fortinet", "ike_gateway_detail"): {"tunnel": "netops-g14"},
    ("cisco_nxos", "log_messages"): {},
    ("cisco_nxos", "log_history"): {"count": "40"},
    ("cisco_nxos", "ntp_associations"): {},
    ("cisco_nxos", "hsrp_detail"): {},
    ("cisco_nxos", "vrrp_detail"): {},
    ("cisco_nxos", "vrrpv3_detail"): {},
    ("cisco_nxos", "object_tracking"): {},
    ("cisco_nxos", "port_channel_database"): {},
    ("cisco_nxos", "vpc_member_consistency"): {"vpc_id": "129"},
    ("cisco_nxos", "ipv4_access_lists"): {"name": "acl-example"},
    ("cisco_nxos", "ipv6_access_lists"): {},
    ("cisco_nxos", "mac_access_lists"): {},
    ("cisco_nxos", "ipv4_access_lists_summary"): {},
    ("cisco_nxos", "ipv6_access_lists_summary"): {},
    ("cisco_nxos", "mac_access_lists_summary"): {},
    ("cisco_nxos", "arp_inspection_statistics"): {},
    ("cisco_nxos", "arp_inspection_statistics_vlan"): {"vlan_id": "20"},
    ("cisco_xe", "vrfs"): {},
    ("cisco_xe", "vrf_arp_table"): {"vrf": "default"},
    ("cisco_xe", "ospfv3_neighbors"): {},
    ("cisco_xe", "ipv6_interface_details"): {"interface": "Vlan10"},
    ("cisco_xe", "bfd_neighbors"): {},
    ("cisco_xe", "route_maps"): {},
    ("cisco_xe", "ntp_associations"): {},
    ("cisco_xe", "lacp_neighbors"): {},
    ("cisco_xe", "hsrp_summary"): {},
    ("cisco_xe", "stp_root"): {},
    ("cisco_xe", "arp_table"): {},
    ("cisco_xe", "ipv6_neighbors"): {},
    ("cisco_xe", "mac_table"): {},
    ("cisco_xe", "lldp_neighbors"): {},
    ("cisco_xe", "cdp_neighbors"): {},
    ("cisco_ios", "hsrp_detail"): {},
    ("cisco_ios", "vrrp_detail"): {},
    ("cisco_ios", "object_tracking"): {},
    ("cisco_ios", "ntp_associations"): {},
    ("cisco_xe", "hsrp_detail"): {},
    ("cisco_xe", "vrrp_detail"): {},
    ("cisco_xe", "object_tracking"): {},
    ("cisco_xe", "arp_lookup"): {"address": "192.0.2.1"},
    ("cisco_xe", "arp_lookup_vrf"): {"vrf": "default", "address": "192.0.2.1"},
    ("cisco_xe", "arp_table_vrf"): {"vrf": "default"},
    ("cisco_xe", "ipv6_neighbors_interface"): {"interface": "Vlan10"},
    ("cisco_xe", "ipv6_neighbors_vrf"): {"vrf": "default"},
    ("cisco_xe", "ipv6_neighbors_interface_vrf"): {"interface": "Vlan10", "vrf": "default"},
    ("cisco_xe", "ipv4_access_lists"): {},
    ("cisco_xe", "ipv6_access_lists"): {},
    ("cisco_xe", "dhcp_server_pools"): {},
    ("cisco_xe", "dot1x_interface"): {"interface": "Ethernet0/1"},
    ("cisco_xe", "ip_source_guard"): {},
    ("cisco_ios", "arp_lookup"): {"address": "192.0.2.1"},
    ("cisco_ios", "arp_lookup_vrf"): {"vrf": "default", "address": "192.0.2.1"},
    ("cisco_ios", "arp_table_vrf"): {"vrf": "default"},
    ("cisco_ios", "ipv6_neighbors_interface"): {"interface": "Vlan10"},
    ("cisco_ios", "ipv6_neighbors_vrf"): {"vrf": "default"},
    ("cisco_ios", "ipv6_neighbors_interface_vrf"): {"interface": "Vlan10", "vrf": "default"},
    ("cisco_ios", "ipv4_access_lists"): {},
    ("cisco_ios", "ipv6_access_lists"): {},
    ("cisco_ios", "dhcp_server_pools"): {},
    ("cisco_ios", "dot1x_interface"): {"interface": "GigabitEthernet1/0"},
    ("cisco_ios", "aaa_servers"): {},
    ("cisco_ios", "tacacs_statistics"): {},
    ("cisco_ios", "etherchannel_detail"): {},
    ("cisco_ios", "lacp_internal"): {},
    ("cisco_ios", "vrfs"): {},
    ("cisco_ios", "route_maps"): {},
    ("cisco_ios", "ospfv3_neighbors"): {},
    ("cisco_ios", "bfd_neighbors"): {},
    ("cisco_ios", "ipv6_route_table"): {},
    ("cisco_ios", "arp_table"): {},
    ("cisco_ios", "ipv6_neighbors"): {},
    ("cisco_ios", "mac_table"): {},
    ("cisco_ios", "lldp_neighbors"): {},
    ("cisco_ios", "cdp_neighbors"): {},
    ("cisco_xe", "aaa_servers"): {},
    ("cisco_xe", "tacacs_statistics"): {},
    ("cisco_xe", "etherchannel_detail"): {"group_id": "1"},
    ("cisco_xe", "lacp_internal"): {},
    ("extreme_exos", "ospf_neighbors"): {},
    ("extreme_exos", "ospf_lsdb"): {},
    ("extreme_exos", "bfd_sessions"): {},
    ("extreme_exos", "arp_table"): {},
    ("extreme_exos", "ipv6_neighbors"): {},
    ("extreme_exos", "mac_table"): {},
    ("extreme_exos", "lldp_neighbors"): {},
    ("extreme_exos", "lldp_neighbors_detail"): {},
    ("extreme_exos", "access_list_counters"): {},
    ("arista_eos", 'ospf_neighbors_detail'): {},
    ("arista_eos", 'ospf_neighbors_detail_vrf'): {'vrf': 'default'},
    ("arista_eos", 'ospf_interface_detail'): {'interface': 'Vlan10'},
    ("arista_eos", 'ospf_interface_detail_vrf'): {'interface': 'Vlan10', 'vrf': 'default'},
    ("arista_eos", 'ospf_database'): {},
    ("arista_eos", 'ospf_database_vrf'): {'vrf': 'default'},
    ("arista_eos", 'ospfv3_interface_detail'): {'interface': 'Vlan10'},
    ("arista_eos", 'ospfv3_interface_detail_vrf'): {'interface': 'Vlan10', 'vrf': 'default'},
    ("arista_eos", 'ospfv3_database'): {},
    ("arista_eos", 'ospfv3_database_vrf'): {'vrf': 'default'},
    ("arista_eos", 'ospfv3_neighbors_vrf'): {'vrf': 'default'},
    ("arista_eos", 'vrrp'): {},
    ("arista_eos", 'vrrp_vrf'): {'vrf': 'default'},
    ("arista_eos", 'bfd_peers'): {},
    ("arista_eos", 'bfd_peers_vrf'): {'vrf': 'default'},
    ("arista_eos", 'interface_queue_counters'): {'interface': 'Ethernet2'},
    ("arista_eos", 'ipv4_access_lists_summary'): {},
    ("arista_eos", 'ipv6_access_lists_summary'): {},
    ("arista_eos", 'ipv4_access_lists_interface'): {'interface': 'Ethernet2'},
    ("arista_eos", 'ipv6_access_lists_interface'): {'interface': 'Ethernet2'},
    ("arista_eos", 'ipv4_access_lists'): {},
    ("arista_eos", 'ipv6_access_lists'): {},
    ("arista_eos", 'aaa_sessions'): {},
    ("arista_eos", 'snmp_targets'): {},
    ("arista_eos", 'dot1x_interface'): {'interface': 'Ethernet2'},
    ("arista_eos", 'dot1x_clients'): {'interface': 'Ethernet2'},
    ("arista_eos", 'dhcp_server_leases'): {},
    # G120: a log window without a matching message is empty (measured on cEOS 4.36.1F).
    ("arista_eos", "log_messages_last"): {"minutes": "10", "severity": "emergencies"},
    ("arista_eos", "log_messages_range"): {"begin_date": "2026-11-18", "begin_time": "03:00:00",
                                           "end_date": "2026-11-18", "end_time": "03:00:01", "severity": "emergencies"},
    ("fortiadc", "interface_state"): {"interface": "port1"},
    ("fortiadc", "dos_access_limit"): {"virtual_server": "VS_APP_HTTP"},
    ("fortiadc", "dos_conn_limit"): {"virtual_server": "VS_APP_HTTP"},
    ("fortiadc", "dos_req_limit"): {"virtual_server": "VS_APP_HTTP"},
    ("fortiadc", "traffic_group_status"): {},
    ("fortinet", "crash_log"): {},
    ("fortinet", "config_error_log"): {},
    # G132: empty Junos protocol/instance answers measured on vJunos-switch 26.2R1.7.
    ('juniper_junos', 'bgp_peer_received_routes'): {'address': '192.0.2.1'},
    ('juniper_junos', 'bgp_peer_advertised_routes'): {'address': '192.0.2.1'},
    ('juniper_junos', 'ospf_neighbors_detail'): {},
    ('juniper_junos', 'ospf_interface_detail'): {'interface': 'irb.20'},
    ('juniper_junos', 'ospf_database'): {},
    ('juniper_junos', 'ospfv3_neighbors_detail'): {},
    ('juniper_junos', 'ospfv3_interface_detail'): {'interface': 'irb.20'},
    ('juniper_junos', 'ospfv3_database'): {},
    ('juniper_junos', 'arp_table_instance'): {'instance': 'g132'},
    ('juniper_junos', 'ipv6_neighbors_instance'): {'instance': 'g132'},
    ('juniper_junos_els', 'bgp_peer_received_routes'): {'address': '192.0.2.1'},
    ('juniper_junos_els', 'bgp_peer_advertised_routes'): {'address': '192.0.2.1'},
    ('juniper_junos_els', 'ospf_neighbors_detail'): {},
    ('juniper_junos_els', 'ospf_interface_detail'): {'interface': 'irb.20'},
    ('juniper_junos_els', 'ospf_database'): {},
    ('juniper_junos_els', 'ospfv3_neighbors_detail'): {},
    ('juniper_junos_els', 'ospfv3_interface_detail'): {'interface': 'irb.20'},
    ('juniper_junos_els', 'ospfv3_database'): {},
    ('juniper_junos_els', 'arp_table_instance'): {'instance': 'g132'},
    ('juniper_junos_els', 'ipv6_neighbors_instance'): {'instance': 'g132'},
    ('juniper_junos_els', 'mac_table_vlan'): {'vlan': 'default'},
    ('juniper_junos', 'interface_firewall_filter'): {'interface': 'irb.20'},
    ('juniper_junos_els', 'interface_firewall_filter'): {'interface': 'irb.20'},
    **{(profile, query): {} for profile in ("juniper_junos", "juniper_junos_els") for query in (
        "dhcp_server_bindings", "dhcp_relay_bindings", "dns_resolvers", "syslog_status",
        "authentication_order", "radius_servers", "tacacs_servers",
    )},
}
TRAFFIC_GROUP = "get system traffic-group-status brief"


def _fake_read(monkeypatch, output, rc=0):
    calls = []

    def fake(auth, platform, command, prompt=False):
        calls.append((platform, command, prompt))
        return rc, output

    monkeypatch.setattr(engine, "_verified_read", fake)
    return calls


def _read(platform, query, parameters=None):
    auth = dataclasses.replace(_target(platform, query), read_inventory=INVENTORY)
    return engine.ssh_read(auth, platform, query, parameters or {}, 0, 48_000)


def _cases():
    fortinet_query, _ = _plain_query("fortinet")
    prompt_only = engine._pty_body(SLB.encode() + b"\r\n" + ADC_PROMPT, SLB, ADC_PROMPT)
    return [
        ("fortiadc", "slb_load", "\n", "newline"),
        ("fortiadc", "slb_load", "", "empty"),
        ("fortiadc", "slb_load", " \r\n\r\n", "blank-lines"),
        ("fortiadc", "slb_load", prompt_only, "pty-echo-and-prompt-only"),
        ("fortinet", fortinet_query, "\n", "newline"),
        ("fortinet", fortinet_query, "", "empty"),
    ]


def test_prompt_only_pty_answer_reduces_to_empty_body():
    assert engine._pty_body(SLB.encode() + b"\r\n" + ADC_PROMPT, SLB, ADC_PROMPT) == ""


@pytest.mark.parametrize("platform,query,output,label", _cases(), ids=lambda v: v if isinstance(v, str) else None)
def test_whitespace_only_output_is_an_empty_failure(wire, monkeypatch, platform, query, output, label):
    calls = _fake_read(monkeypatch, output, rc=0)
    answer = _read(platform, query)
    assert calls, "fake transport was not used"
    assert answer["ok"] is False and answer["error_code"] == "empty", answer
    assert answer["rc"] == 0 and answer["query"] == query and answer["platform"] == platform
    assert "complete" not in answer and "untrusted_device_output" not in answer
    assert engine._SSH_PAGE_CACHE == {}


def test_empty_code_is_a_triage_missing_reason():
    assert "empty" in triage_slb.MISSING_REASONS


def test_only_catalogue_documented_queries_allow_empty_output():
    allowed = {(platform, name) for platform, queries in READ_QUERIES.items()
               for name, query in queries.items() if query.empty_allowed}
    # The public log history tests have a real buffer, device clock and a
    # filter that can legitimately return zero rows.
    log_history_profiles = ("cisco_ios", "cisco_xe", "extreme_exos", "juniper_junos", "juniper_junos_els")
    assert allowed == set(LEGAL_EMPTY) | {(profile, "log_history") for profile in log_history_profiles}
    cisco_notes = (Path(__file__).resolve().parents[1]
                   / "docs/vendor-cli-references/cisco.md").read_text()
    empty_table = cisco_notes.split("#### Valid empty management output\n", 1)[1].split("\n## ", 1)[0]
    for platform, name in allowed:
        if platform in {"cisco_ios", "cisco_xe"} and f"| `{platform}` | `{name}` | empty output means" in empty_table:
            continue
        assert "empty output means" in READ_QUERIES[platform][name].description


@pytest.mark.parametrize("platform,query", sorted(LEGAL_EMPTY))
@pytest.mark.parametrize("output", ["", "\n"])
def test_catalogue_legal_empty_output_stays_success(wire, monkeypatch, platform, query, output):
    _fake_read(monkeypatch, output)
    answer = _read(platform, query, LEGAL_EMPTY[(platform, query)])
    assert answer["ok"] is True and answer["complete"] is True, answer
    assert answer["untrusted_device_output"] == output and "error_code" not in answer


@pytest.mark.parametrize("diagnostic", [b"", b"Unexpected device diagnostic\n", b"Command authorization failed.\n"])
def test_classic_ios_empty_table_ignores_login_banner_but_keeps_command_errors(wire, monkeypatch, diagnostic):
    fixtures = Path(__file__).parent / 'fixtures/real/cisco_ios/iosv_15.9.3M12_g51'
    calls = []

    def transport(_address, _port, _login, _credential, _host_key, command, **options):
        stdout, stderr = (fixtures / 'version.out').read_bytes(), b''
        if command == 'show route-map':
            stdout = (fixtures / 'route_maps.out').read_bytes()
            stderr = diagnostic
            if not options.get('suppress_login_banner'):
                stderr = b'Authorized use only.\n' + stderr
            calls.append(command)
        return engine.core_ssh.Result(rc=0, stdout=stdout, stderr=stderr, said='', started_at='', finished_at='')

    monkeypatch.setattr(engine.core_ssh, 'run_command', transport)
    answer = _read('cisco_ios', 'route_maps')
    assert calls == ['show route-map']
    if diagnostic:
        assert answer['ok'] is False and answer['error_code'] == 'device_cli_error'
    else:
        assert answer['ok'] is True and answer['status'] == 'empty'


IOS_XE_BLANK_CAPTURES = [
    ("ntp_associations", "iolxe_17.18.2_g72/d-iolxe-l2-ro-ntp_associations.out"),
    ("lacp_neighbors", "iolxe_17.18.2/lacp_neighbors.txt"),
    ("hsrp_summary", "iolxe_17.18.2/hsrp_summary.txt"),
    ("stp_root", "iolxe_17.18.2/stp_root.txt"),
]


def _ios_xe_blank_capture(capture):
    path = Path(__file__).parent / "fixtures" / "real" / "cisco_xe" / capture
    output = path.read_text()
    assert not output.strip()
    return output


@pytest.mark.parametrize("query,capture", IOS_XE_BLANK_CAPTURES)
def test_ios_xe_empty_tables_and_failed_reads_are_distinct(wire, monkeypatch, query, capture):
    output = _ios_xe_blank_capture(capture)
    calls = _fake_read(monkeypatch, output)
    result = _read("cisco_xe", query)
    assert calls and result["ok"] and result["complete"] and result["status"] == "empty", result
    assert result["normalized"]["records"] == []
    _fake_read(monkeypatch, output, rc=1)
    failed = _read("cisco_xe", query)
    assert not failed["ok"] and failed["error_code"] == "device_cli_error"
    _fake_read(monkeypatch, "% Invalid input detected at '^' marker.\n")
    refused = _read("cisco_xe", query)
    assert not refused["ok"] and refused["error_code"] == "device_cli_error"


@pytest.mark.parametrize("query,capture", IOS_XE_BLANK_CAPTURES)
@pytest.mark.parametrize("rc,notice,allowed", [
    (0, f"Connection to {LOOPBACK} closed by remote host.", True),
    (0, f"Connection to {LOOPBACK} port {PORT} closed by remote host.", True),
    (1, f"Connection to {LOOPBACK} closed by remote host.", False),
    (0, f"Connection to {LOOPBACK} port {PORT + 1} closed by remote host.", False),
    (0, "Connection to 192.0.2.99 closed by remote host.", False),
    (0, f"Connection to {LOOPBACK} closed by remote host.\nSSH channel failure", False),
    (0, f"Connection to {LOOPBACK} closed by remote host.\n% Invalid input detected at '^' marker.", False),
])
def test_ios_xe_empty_tables_accept_only_the_successful_peer_close(wire, monkeypatch, query, capture, rc, notice, allowed):
    # DERIVED: replay the captured empty body with the IOL OpenSSH close framing also measured in G71.
    stdout = _ios_xe_blank_capture(capture).encode() or b"\r\n\r\n"
    real_run = engine.core_ssh.run_command
    expected = READ_QUERIES["cisco_xe"][query].command

    def transport(host, port, login, credential, host_key, command, **options):
        if command == expected:
            return Result(rc, stdout, "", "t0", "t1", stderr=(notice + "\n").encode())
        return real_run(host, port, login, credential, host_key, command, **options)

    monkeypatch.setattr(engine.core_ssh, "run_command", transport)
    result = _read("cisco_xe", query)
    if allowed:
        assert result["ok"] and result["complete"] and result["status"] == "empty", result
        assert result["normalized"]["records"] == []
    else:
        assert not result["ok"] and result["error_code"] == "device_cli_error", result


@pytest.mark.parametrize("platform", ["fortiadc", "fortinet"])
def test_control_non_empty_output_stays_success(wire, monkeypatch, platform):
    query = "slb_load" if platform == "fortiadc" else _plain_query("fortinet")[0]
    _fake_read(monkeypatch, "VS_APP_HTTP status 1\n")
    answer = _read(platform, query)
    assert answer["ok"] is True and answer["complete"] is True


@pytest.mark.parametrize("prompt", [b"(P) fortiadc-767-b # ", b"(S) FortiADC-KVM # "])
def test_an_ha_pair_without_traffic_groups_reads_as_an_empty_success(wire, monkeypatch, prompt):
    _fortinet_wire(wire, {"get system status": FORTIADC_STATUS, TRAFFIC_GROUP: "\n"}, prompt=prompt.decode())
    answer = _read("fortiadc", "traffic_group_status")
    assert wire["transcript"].read_text().splitlines() == ["get system status", TRAFFIC_GROUP]
    assert answer["ok"] is True and answer["complete"] is True and answer["transport"] == "pty", answer
    assert answer["untrusted_device_output"] == "" and "error_code" not in answer
    meaning = READ_QUERIES["fortiadc"]["traffic_group_status"].description
    for part in ("Administration Guide (p. 246) describes traffic groups for the HA mode active-active-VRRP",
                 "empty output means the device reports no traffic group",
                 "measured in active-passive mode (both roles) and in standalone mode",
                 "each time with an empty config system traffic-group section",
                 "names a predefined traffic group default",
                 "In active-active-VRRP empty output was not measured",
                 "check it against ha_status and the traffic group configuration"):
        assert part in meaning
    for claim in ("used only in", "is not expected", "which is expected"):
        assert claim not in meaning
    assert "error" not in meaning.lower() and "ha_status" in READ_QUERIES["fortiadc"]
