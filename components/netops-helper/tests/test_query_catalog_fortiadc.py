from __future__ import annotations

from netops_helper import read_policy
from netops_helper.query_catalog.fortiadc import QUERIES


EXPECTED = {
    "system_status": ("get system status", {}, False),
    "system_performance": ("get system performance", {}, False),
    "vm_license": ("diagnose system vm", {}, False),
    "interface_state": (
        "diagnose netlink interface list {interface}",
        {"interface": ("interfaces", "fortiadc_interface")},
        False,
    ),
    "interface_counters": ("diagnose netlink device", {}, False),
    "routing_table": ("get router info routing-table all", {}, True),
    "arp_table": ("diagnose netlink neighbor list", {}, True),
    "firewall_timeouts": ("get firewall global", {}, False),
    "slb_load": ("diagnose server-load-balance slb_load", {}, True),
    "tls_handshake_stats": (
        "execute ssl-handshake-n-record-statistics show virtual-server {virtual_server}",
        {"virtual_server": ("adc_virtual_servers", "fortiadc_virtual_server")},
        False,
    ),
    "tls_session_reuse": (
        "execute ssl-client-side-session-statistics show virtual-server {virtual_server}",
        {"virtual_server": ("adc_virtual_servers", "fortiadc_virtual_server")},
        False,
    ),
    "dos_access_limit": (
        "execute dos get dos-access-limit {virtual_server}",
        {"virtual_server": ("adc_virtual_servers", "fortiadc_virtual_server")},
        False,
    ),
    "dos_conn_limit": (
        "execute dos get dos-conn-limit {virtual_server}",
        {"virtual_server": ("adc_virtual_servers", "fortiadc_virtual_server")},
        False,
    ),
    "dos_req_limit": (
        "execute dos get dos-req-limit {virtual_server}",
        {"virtual_server": ("adc_virtual_servers", "fortiadc_virtual_server")},
        False,
    ),
    "waf_signature_status": ("get security waf-signature-status", {}, False),
    "slb_vs_stat": (
        "diagnose server-load-balance vs_stat vdom {vdom} vs {virtual_server}",
        {
            "vdom": ("adc_vdoms", "fortiadc_vdom"),
            "virtual_server": ("adc_virtual_servers", "fortiadc_virtual_server"),
        },
        True,
    ),
    "cpu_info": ("diagnose hardware get sysinfo cpu", {}, True),
    "slb_sessions": ("diagnose server-load-balance session list", {}, True),
    "persistence_sessions": ("diagnose server-load-balance persistence list", {}, True),
    "nic_detail": (
        "diagnose hardware get deviceinfo nic-detail {interface}",
        {"interface": ("interfaces", "fortiadc_interface")},
        False,
    ),
    "waf_block_ip": ("execute waf block-ip list", {}, True),
    "log_list_traffic": ("execute log list-type tlog", {}, True),
    "log_list_attack": ("execute log list-type alog", {}, True),
    "autoupdate_contract": ("execute autoupdate contract", {}, False),
    "system_date": ("execute date", {}, False),
    "log_files": ("execute log list-type all", {}, True),
    "lldp_neighbors": ("diagnose lldprx neighbor summary", {}, True),
    "bgp_summary": ("get router info bgp summary", {}, False),
    "bgp_neighbors": ("get router info bgp neighbors", {}, True),
    "ospf_neighbors": ("get router info ospf neighbor", {}, True),
    "ha_status": ("get system ha-status", {}, False),
    "traffic_group_status": ("get system traffic-group-status brief", {}, False),
    "llb_policy": ("diagnose llb policy list", {}, True),
}
INVENTORY = {
    "interfaces": ("port1", "haport0"),
    "adc_vdoms": ("root",),
    "adc_virtual_servers": ("VS_APP_HTTP",),
}
PARAMETERS = {"interface": "port1", "vdom": "root", "virtual_server": "VS_APP_HTTP"}


def _rejected(parameters, inventory=INVENTORY) -> bool:
    try:
        read_policy.render_read_query("fortiadc", "interface_state", parameters, inventory)
    except ValueError:
        return True
    return False


def test_exact_commands_slots_and_volume() -> None:
    assert {
        name: (
            query.command,
            {slot: (s.inventory, s.kind) for slot, s in query.slots.items()},
            query.high_volume,
        )
        for name, query in QUERIES.items()
    } == EXPECTED
    assert read_policy._FORTIADC_COMMANDS == {query.command for query in QUERIES.values()}


def test_only_the_qualified_adc_reads_use_a_terminal() -> None:
    assert {name for name, query in QUERIES.items() if query.pty} == {
        "routing_table", "slb_load", "slb_vs_stat", "tls_handshake_stats", "tls_session_reuse",
        "bgp_summary", "bgp_neighbors", "ospf_neighbors",
        "dos_access_limit", "dos_conn_limit", "dos_req_limit",
        "lldp_neighbors", "traffic_group_status", "llb_policy",
    }
    assert {
        (platform, name)
        for platform, queries in read_policy.READ_QUERIES.items() if platform != "fortiadc"
        for name, query in queries.items() if query.pty
    } == {("fortinet", "dns_cache"), ("fortinet", "fqdn_cache")}


def test_every_query_renders_its_exact_allowed_command() -> None:
    for name, (command, slots, _) in EXPECTED.items():
        parameters = {slot: PARAMETERS[slot] for slot in slots}
        assert read_policy.render_read_query("fortiadc", name, parameters, INVENTORY) == (
            "fortiadc", command.format(**parameters),
        )


def test_interface_state_accepts_only_an_enrolled_interface() -> None:
    assert read_policy.render_read_query(
        "fortiadc", "interface_state", {"interface": "haport0"}, INVENTORY,
    ) == ("fortiadc", "diagnose netlink interface list haport0")
    for value in ("port9", "port1; get system status", "", "port1 port2"):
        assert _rejected({"interface": value}), value
    assert _rejected({"interface": "all"}, {"interfaces": ("all",)})
    assert _rejected({})


def test_waf_signature_status_renders_exact_command() -> None:
    assert read_policy.render_read_query("fortiadc", "waf_signature_status", {}, INVENTORY) == (
        "fortiadc", "get security waf-signature-status",
    )


def test_slb_vs_stat_renders_with_enrolled_vdom_and_virtual_server() -> None:
    assert read_policy.render_read_query(
        "fortiadc", "slb_vs_stat", {"vdom": "root", "virtual_server": "VS_APP_HTTP"}, INVENTORY,
    ) == ("fortiadc", "diagnose server-load-balance vs_stat vdom root vs VS_APP_HTTP")


def test_slb_vs_stat_accepts_only_enrolled_objects_of_their_own_category() -> None:
    def rejected(parameters, inventory=INVENTORY) -> bool:
        try:
            read_policy.render_read_query("fortiadc", "slb_vs_stat", parameters, inventory)
        except ValueError:
            return True
        return False

    for value in ("VS_OTHER", "VS_APP_HTTP; get system status", "", "VS_APP_HTTP rs RS_A"):
        assert rejected({"vdom": "root", "virtual_server": value}), value
    for value in ("other", "root; get system status", ""):
        assert rejected({"vdom": value, "virtual_server": "VS_APP_HTTP"}), value
    assert rejected(
        {"vdom": "root", "virtual_server": "root"},
        {"adc_vdoms": ("root",), "adc_virtual_servers": ("VS_APP_HTTP",)},
    )
    assert rejected({"vdom": "root"})
    assert rejected({"virtual_server": "VS_APP_HTTP"})
    for query in ("tls_handshake_stats", "tls_session_reuse", "dos_access_limit", "dos_conn_limit", "dos_req_limit"):
        for parameters, inventory in (
            ({"virtual_server": "VS_OTHER"}, INVENTORY),
            ({"virtual_server": "VS_APP_HTTP; clean"}, INVENTORY),
            ({"virtual_server": "VS_APP_HTTP"}, {"adc_vdoms": ("VS_APP_HTTP",)}),
            ({"virtual_server": "VS_APP_HTTP", "datasource": "clean"}, INVENTORY),
        ):
            try:
                read_policy.render_read_query("fortiadc", query, parameters, inventory)
            except ValueError:
                continue
            raise AssertionError((query, parameters))


def test_nic_detail_accepts_only_an_enrolled_interface() -> None:
    def rejected(parameters, inventory=INVENTORY) -> bool:
        try:
            read_policy.render_read_query("fortiadc", "nic_detail", parameters, inventory)
        except ValueError:
            return True
        return False

    assert read_policy.render_read_query(
        "fortiadc", "nic_detail", {"interface": "port1"}, INVENTORY,
    ) == ("fortiadc", "diagnose hardware get deviceinfo nic-detail port1")
    for value in ("port9", "port1; get system status", "", "port1 port2"):
        assert rejected({"interface": value}), value
    assert rejected({})


def test_execute_reads_are_only_the_exact_list_views() -> None:
    executes = {query.command for query in QUERIES.values() if query.command.startswith("execute ")}
    assert executes == {
        "execute waf block-ip list",
        "execute log list-type tlog",
        "execute log list-type alog",
        "execute autoupdate contract",
        "execute ssl-handshake-n-record-statistics show virtual-server {virtual_server}",
        "execute ssl-client-side-session-statistics show virtual-server {virtual_server}",
        "execute dos get dos-access-limit {virtual_server}",
        "execute dos get dos-conn-limit {virtual_server}",
        "execute dos get dos-req-limit {virtual_server}",
        "execute date",
        "execute log list-type all",
    }
    for name in ("waf_block_ip", "log_list_traffic", "log_list_attack", "autoupdate_contract", "system_date", "log_files"):
        try:
            read_policy.render_read_query("fortiadc", name, {"interface": "port1"}, INVENTORY)
        except ValueError:
            continue
        raise AssertionError(name)
