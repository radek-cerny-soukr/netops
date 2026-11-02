"""Boundary contracts of the proxy argument, scope and rate checks.

Each case pins one edge of a limit the proxy enforces before anything is
forwarded: the last accepted value and the first refused one.
"""

from __future__ import annotations

from collections import deque
from types import SimpleNamespace

import pytest

from netops_helper import proxy as MODULE

Proxy = MODULE.Proxy
ALIAS = "lab-fw"
SSH = {"platform": "fortios", "query": "system_status"}
DIAG = {"recipe": "ping", "address": "192.0.2.10", "interface": "port1"}
ADC = {"recipe": "ping", "address": "192.0.2.10", "interface": ""}
ADC_NAME = "update.fortiguard.net"
ADC_URL = "http://192.0.2.10/health"
ADC_HC = {"recipe": "health_check_verify", "address": "192.0.2.10", "interface": "", "health_check": "HC_HTTP_APP"}
FTP = {"remote_path": "/safe"}


def _call(tool: str, extra: dict) -> dict:
    return Proxy._validate_tool_arguments(tool, {"target": ALIAS, **extra})


ACCEPTED = [
    ("tcp_probe", {"port": 1}),
    ("tcp_probe", {"port": 65_535}),
    ("tcp_probe", {"port": 22, "timeout": 0.2}),
    ("tcp_probe", {"port": 22, "timeout": 0.5}),
    ("tcp_probe", {"port": 22, "timeout": 1}),
    ("tcp_probe", {"port": 22, "timeout": 15.0}),
    ("ssh_read", {**SSH, "offset": 0, "max_bytes": 1_000}),
    ("ssh_read", {**SSH, "offset": 8_000_000, "max_bytes": 48_000}),
    ("ssh_read", {**SSH, "max_bytes": 1_000}),
    ("icmp_probe", {"count": 1}),
    ("icmp_probe", {"count": 8}),
    ("ftp_list", {"remote_path": "/", "use_tls": True, "acknowledge_unencrypted": False}),
    ("ftp_list", {"remote_path": "/" + "a" * 1_999}),
    ("ftp_list", {"remote_path": "/a b!"}),
    ("tls_probe", {"server_name": "a"}),
    ("tls_probe", {"server_name": "a" * 253}),
    ("tls_probe", {"server_name": "a b"}),
    ("tls_probe", {"server_name": None}),
    *[("fortios_diagnostics", {**DIAG, "recipe": recipe})
      for recipe in ("ping", "traceroute", "sniffer", "sessions", "flow", "logs")],
    ("fortios_diagnostics", {**DIAG, "vdom": "root"}),
    ("fortios_diagnostics", {**DIAG, "recipe": "traceroute", "count": 1}),
    ("fortios_diagnostics", {**DIAG, "recipe": "traceroute", "count": 3}),
    ("fortios_diagnostics", {**DIAG, "recipe": "ping", "count": 8}),
    ("fortios_diagnostics", {**DIAG, "timeout": 1}),
    ("fortios_diagnostics", {**DIAG, "timeout": 10}),
    ("fortios_diagnostics", {**DIAG, "max_bytes": 1_000}),
    ("fortios_diagnostics", {**DIAG, "max_bytes": 16_000}),
    ("fortios_diagnostics", {**ADC, "timeout": 10}),
    ("fortios_diagnostics", {**ADC, "recipe": "traceroute", "timeout": 60}),
    ("fortios_diagnostics", {**ADC, "recipe": "nslookup", "address": ADC_NAME, "count": 3}),
    ("fortios_diagnostics", {**ADC, "recipe": "http_probe", "address": ADC_URL}),
    ("fortios_diagnostics", {**ADC_HC, "count": 1}),
    ("fortios_diagnostics", {**ADC_HC, "count": 5}),
    ("fortios_diagnostics", {**ADC_HC, "count": 5, "timeout": 60}),
    ("schema_read", {"path": "system interface"}),
    ("schema_read", {"path": "a" * 128}),
    ("schema_read", {"path": "System Interface"}),
    ("schema_read", {"path": "system", "view": "show"}),
    ("schema_read", {"path": "system", "view": "get"}),
    ("schema_read", {"path": "system", "vdom": "root"}),
    ("schema_read", {"path": "system", "vdom": "v" * 128}),
    ("schema_read", {"path": "system", "owners": ["a"]}),
    ("schema_read", {"path": "system", "owners": ["a"] * 64}),
    ("schema_read", {"path": "system", "owners": ["k" * 128]}),
    ("ssh_read", {**SSH, "parameters": {f"p{index}": "v" for index in range(16)}}),
    ("ssh_read", {**SSH, "parameters": {"n": "v"}}),
    ("ssh_read", {**SSH, "parameters": {"a b!": "c d!"}}),
    ("ssh_read", {**SSH, "parameters": {"n" * 128: "v" * 128}}),
    ("snmp_get", {"oids": ["1"]}),
    ("snmp_get", {"oids": ["1.3"] * 20}),
    ("snmp_get", {"oids": ["1" * 200]}),
    ("snmp_get", {"oids": ["1 3!"]}),
]

REFUSED = [
    ("tcp_probe", {"port": 0}),
    ("tcp_probe", {"port": 65_536}),
    ("tcp_probe", {"port": True}),
    ("tcp_probe", {"port": 22, "timeout": 0.1}),
    ("tcp_probe", {"port": 22, "timeout": 15.5}),
    ("tcp_probe", {"port": 22, "timeout": 20}),
    ("tcp_probe", {"port": 22, "timeout": 100}),
    ("tcp_probe", {"port": 22, "timeout": True}),
    ("tcp_probe", {"port": 22, "timeout": "5"}),
    ("tcp_probe", {"port": 22, "timeout": float("nan")}),
    ("tcp_probe", {"port": 22, "timeout": float("inf")}),
    ("ssh_read", {**SSH, "offset": -1}),
    ("ssh_read", {**SSH, "offset": True}),
    ("ssh_read", {**SSH, "offset": 8_000_001}),
    ("ssh_read", {**SSH, "max_bytes": 999}),
    ("ssh_read", {**SSH, "max_bytes": 0}),
    ("ssh_read", {**SSH, "max_bytes": 48_001}),
    ("ssh_read", {**SSH, "offset": 0, "max_bytes": 999}),
    ("icmp_probe", {"count": 0}),
    ("icmp_probe", {"count": 9}),
    ("icmp_probe", {"count": True}),
    ("icmp_probe", {"count": "1"}),
    ("ftp_list", {**FTP, "acknowledge_unencrypted": "yes"}),
    ("ftp_list", {**FTP, "use_tls": "yes"}),
    ("ftp_list", {"remote_path": ""}),
    ("ftp_list", {"remote_path": "/" + "a" * 2_000}),
    ("ftp_list", {"remote_path": "/a\x01b"}),
    ("ftp_list", {"remote_path": "/a\x7fb"}),
    ("ftp_list", {"remote_path": 5}),
    ("tls_probe", {"server_name": ""}),
    ("tls_probe", {"server_name": "a" * 254}),
    ("tls_probe", {"server_name": "a\x01"}),
    ("tls_probe", {"server_name": "a\x7f"}),
    ("fortios_diagnostics", {**DIAG, "recipe": "bogus"}),
    ("fortios_diagnostics", {**DIAG, "address": "0.0.0.0"}),
    ("fortios_diagnostics", {**DIAG, "address": "224.0.0.0"}),
    ("fortios_diagnostics", {**DIAG, "address": "255.255.255.255"}),
    ("fortios_diagnostics", {**DIAG, "vdom": "-root"}),
    ("fortios_diagnostics", {**DIAG, "recipe": "traceroute", "count": 4}),
    ("fortios_diagnostics", {**DIAG, "recipe": "traceroute", "count": 5}),
    ("fortios_diagnostics", {**DIAG, "count": 0}),
    ("fortios_diagnostics", {**DIAG, "timeout": 11}),
    ("fortios_diagnostics", {**DIAG, "max_bytes": 999}),
    ("fortios_diagnostics", {**DIAG, "max_bytes": 16_001}),
    ("fortios_diagnostics", {**DIAG, "recipe": "traceroute", "timeout": 60}),
    ("fortios_diagnostics", {**ADC, "timeout": 11}),
    ("fortios_diagnostics", {**ADC, "recipe": "traceroute", "timeout": 61}),
    ("fortios_diagnostics", {**ADC, "count": 5}),
    ("fortios_diagnostics", {**ADC, "recipe": "sniffer"}),
    ("fortios_diagnostics", {**ADC, "address": ADC_NAME}),
    ("fortios_diagnostics", {**ADC, "recipe": "nslookup"}),
    ("fortios_diagnostics", {**ADC, "recipe": "nslookup", "address": "Update.FortiGuard.net"}),
    ("fortios_diagnostics", {**DIAG, "recipe": "nslookup", "address": ADC_NAME}),
    ("fortios_diagnostics", {**ADC, "recipe": "http_probe", "address": "192.0.2.10"}),
    ("fortios_diagnostics", {**ADC, "recipe": "http_probe", "address": "https://192.0.2.10/health"}),
    ("fortios_diagnostics", {**ADC, "recipe": "http_probe", "address": ADC_URL + " -X POST"}),
    ("fortios_diagnostics", {**ADC, "recipe": "http_probe", "address": ADC_URL, "count": 1}),
    ("fortios_diagnostics", {**DIAG, "recipe": "http_probe", "address": ADC_URL}),
    ("fortios_diagnostics", {**ADC_HC, "count": 0}),
    ("fortios_diagnostics", {**ADC_HC, "count": 6}),
    ("fortios_diagnostics", {**ADC_HC, "timeout": 61}),
    ("fortios_diagnostics", {**ADC, "recipe": "http_probe", "address": ADC_URL, "timeout": 11}),
    ("fortios_diagnostics", {**ADC_HC, "health_check": "HC_HTTP_APP port 80"}),
    ("fortios_diagnostics", {key: value for key, value in ADC_HC.items() if key != "health_check"}),
    ("fortios_diagnostics", {**ADC, "health_check": "HC_HTTP_APP"}),
    ("schema_read", {"path": "a" * 129}),
    ("schema_read", {"path": "-bad"}),
    ("schema_read", {"path": 5}),
    ("schema_read", {"path": "system", "view": "set"}),
    ("schema_read", {"path": "system", "vdom": ""}),
    ("schema_read", {"path": "system", "vdom": "v" * 129}),
    ("schema_read", {"path": "system", "vdom": "a\n"}),
    ("schema_read", {"path": "system", "owners": "a"}),
    ("schema_read", {"path": "system", "owners": ["a"] * 65}),
    ("schema_read", {"path": "system", "owners": [1]}),
    ("schema_read", {"path": "system", "owners": [""]}),
    ("schema_read", {"path": "system", "owners": ["k" * 129]}),
    ("schema_read", {"path": "system", "owners": ["a\n"]}),
    ("ssh_read", {**SSH, "parameters": {f"p{index}": "v" for index in range(17)}}),
    ("ssh_read", {**SSH, "parameters": {"": "v"}}),
    ("ssh_read", {**SSH, "parameters": {1: "v"}}),
    ("ssh_read", {**SSH, "parameters": {"a\x01": "v"}}),
    ("ssh_read", {**SSH, "parameters": {"\x7f": "v"}}),
    ("ssh_read", {**SSH, "parameters": {"n" * 129: "v"}}),
    ("ssh_read", {**SSH, "parameters": {"n": "v" * 129}}),
    ("ssh_read", {**SSH, "parameters": {"n": "a\x01"}}),
    ("ssh_read", {**SSH, "parameters": {"n": "a\x7f"}}),
    ("snmp_get", {"oids": []}),
    ("snmp_get", {"oids": "1.3"}),
    ("snmp_get", {"oids": ["1"] * 21}),
    ("snmp_get", {"oids": [""]}),
    ("snmp_get", {"oids": ["1" * 201]}),
    ("snmp_get", {"oids": ["1\x01"]}),
    ("snmp_get", {"oids": ["1\x7f"]}),
]


@pytest.mark.parametrize(("tool", "extra"), ACCEPTED)
def test_the_last_value_inside_each_argument_limit_is_accepted(tool, extra) -> None:
    normalized = _call(tool, extra)
    assert normalized["target"] == ALIAS


@pytest.mark.parametrize(("tool", "extra"), REFUSED)
def test_the_first_value_outside_each_argument_limit_is_refused(tool, extra) -> None:
    with pytest.raises(MODULE.ToolArgumentsError):
        _call(tool, extra)


@pytest.mark.parametrize("alias", ["a", "a" * 128, "a!b", "x~"])
def test_alias_limits_accept_printable_names_up_to_128(alias) -> None:
    assert Proxy._valid_alias(alias)
    assert _call("dns_probe", {} | {"target": alias})["target"] == alias


@pytest.mark.parametrize("alias", ["", "a" * 129, "a b", "a\x7f", "a\x00", None])
def test_alias_limits_refuse_empty_long_and_control_names(alias) -> None:
    assert not Proxy._valid_alias(alias)


def _adc_section(icmp=False, dns=False, queries=("system_status",), **inventory) -> SimpleNamespace:
    granted = {"diagnostic_recipes": ("ping", "traceroute", "nslookup", "http_probe", "health_check_verify"),
               "addresses": ("192.0.2.10",), "diagnostic_names": (ADC_NAME,),
               "diagnostic_http_endpoints": (ADC_URL,), "adc_health_checks": ("HC_HTTP_APP",)}
    granted.update(inventory)
    return SimpleNamespace(egress={"allow_icmp": icmp, "allow_dns": dns}, catalog_platform=lambda: "fortiadc",
                           enabled_queries=queries, read_inventory=granted)


ADC_GRANTED = [
    ({**ADC}, _adc_section(icmp=True)),
    ({**ADC, "recipe": "traceroute"}, _adc_section()),
    ({**ADC, "recipe": "nslookup", "address": ADC_NAME}, _adc_section(dns=True)),
    ({**ADC, "recipe": "http_probe", "address": ADC_URL}, _adc_section()),
    ({**ADC_HC, "count": 2}, _adc_section()),
]


@pytest.mark.parametrize(("extra", "section"), ADC_GRANTED)
def test_a_fortiadc_diagnostic_needs_only_its_grant_and_host_egress(extra, section) -> None:
    Proxy._authorize_tool("fortios_diagnostics", _call("fortios_diagnostics", extra), None, section)


@pytest.mark.parametrize(("extra", "section"), [
    ({**ADC}, _adc_section(dns=True)),
    ({**ADC, "recipe": "nslookup", "address": ADC_NAME}, _adc_section(icmp=True)),
    ({**ADC}, _adc_section(icmp=True, queries=())),
    ({**ADC}, _adc_section(icmp=True, addresses=())),
    ({**ADC, "recipe": "traceroute"}, _adc_section(icmp=True, diagnostic_recipes=("ping",))),
    ({**ADC, "recipe": "nslookup", "address": ADC_NAME}, _adc_section(dns=True, diagnostic_names=())),
    ({**DIAG}, _adc_section(icmp=True, addresses=("192.0.2.10",))),
    ({**ADC, "recipe": "http_probe", "address": "http://192.0.2.10/"}, _adc_section()),
    ({**ADC, "recipe": "http_probe", "address": ADC_URL}, _adc_section(diagnostic_recipes=("health_check_verify",))),
    ({**ADC_HC}, _adc_section(adc_health_checks=("HC_TCP_APP",))),
    ({**ADC_HC}, _adc_section(addresses=("192.0.2.11",))),
    ({**ADC_HC}, _adc_section(diagnostic_recipes=("http_probe",))),
])
def test_a_fortiadc_diagnostic_without_its_grant_is_refused(extra, section) -> None:
    with pytest.raises(MODULE.PolicyScopeError):
        Proxy._authorize_tool("fortios_diagnostics", _call("fortios_diagnostics", extra), None, section)


def _egress(**ports) -> dict:
    document = {"tcp_ports": [], "tcp_port_ranges": [], "udp_ports": [], "udp_port_ranges": []}
    document.update(ports)
    return document


@pytest.mark.parametrize(("port", "egress"), [
    (1, _egress(tcp_ports=[1])),
    (65_535, _egress(tcp_ports=[65_535])),
    (1_000, _egress(tcp_port_ranges=[(1_000, 2_000)])),
    (2_000, _egress(tcp_port_ranges=[(1_000, 2_000)])),
])
def test_a_listed_port_or_range_edge_is_allowed(port, egress) -> None:
    assert Proxy._port_allowed(port, egress, "tcp") is True


@pytest.mark.parametrize(("port", "egress"), [
    (0, _egress(tcp_ports=[0])),
    (65_536, _egress(tcp_ports=[65_536])),
    (70_000, _egress(tcp_port_ranges=[(60_000, 70_000)])),
    (True, _egress(tcp_ports=[1])),
    ("22", _egress(tcp_ports=["22"])),
    (999, _egress(tcp_port_ranges=[(1_000, 2_000)])),
    (2_001, _egress(tcp_port_ranges=[(1_000, 2_000)])),
])
def test_a_port_outside_1_to_65535_or_the_policy_is_never_allowed(port, egress) -> None:
    assert Proxy._port_allowed(port, egress, "tcp") is False


def test_paths_are_confined_to_roots_without_double_slash_or_suffix_tricks() -> None:
    assert Proxy._path_in_roots("/safe/x", ["/safe/"])
    assert Proxy._path_in_roots("/safe", ["/safe"])
    assert not Proxy._path_in_roots("//safe/x", ["/"])
    assert not Proxy._path_in_roots("/data/x", ["/dataX"])
    assert not Proxy._path_in_roots("/safe2/x", ["/safe"])


@pytest.mark.parametrize(("function", "value", "expected"), [
    (lambda value: MODULE._canonical_cisco_ios_interface(value, False), "Gi0/99", "GigabitEthernet0/99"),
    (lambda value: MODULE._canonical_cisco_ios_interface(value, False), "Gi0/100", None),
    (lambda value: MODULE._canonical_cisco_ios_interface(value, False), "Gi0/5/0", None),
    (lambda value: MODULE._canonical_cisco_ios_interface(value, False), "Gi1/0/1", "GigabitEthernet1/0/1"),
    (lambda value: MODULE._canonical_cisco_nxos_interface(value, False), "Ethernet1/1.1", "Ethernet1/1.1"),
    (lambda value: MODULE._canonical_cisco_nxos_interface(value, False), "Port-channel1.1", "Port-channel1.1"),
    (lambda value: MODULE._canonical_cisco_nxos_interface(value, False), "Port-channel1.4094", "Port-channel1.4094"),
    (lambda value: MODULE._canonical_cisco_nxos_interface(value, False), "Port-channel1.4095", None),
    (lambda value: MODULE._canonical_cisco_nxos_interface(value, False), "Vlan1", "Vlan1"),
    (lambda value: MODULE._canonical_cisco_nxos_interface(value, False), "Tunnel0", "Tunnel0"),
    (lambda value: MODULE._canonical_cisco_xe_interface(value, False), "Port-channel1", "Port-channel1"),
    (lambda value: MODULE._canonical_cisco_xe_interface(value, False), "Vlan1", "vlan 1"),
    (MODULE._canonical_cisco_xe_physical, "FiveGigabitEthernet1/0/1", "FiveGigabitEthernet1/0/1"),
    (MODULE._canonical_cisco_xe_physical, "TwentyFiveGigE1/1/1", "TwentyFiveGigE1/1/1"),
    (MODULE._canonical_cisco_xe_physical, "HundredGigE1/0/1", "HundredGigE1/0/1"),
    (MODULE._canonical_cisco_xe_physical, "HundredGigE1/1/1", "HundredGigE1/1/1"),
    (MODULE._canonical_cisco_xe_physical, "Gi1/0/48", "GigabitEthernet1/0/48"),
    (MODULE._canonical_cisco_xe_physical, "Gi1/1/1", "GigabitEthernet1/1/1"),
    (MODULE._canonical_cisco_xe_physical, "Gi1/0/49", None),
    (MODULE._canonical_cisco_xe_physical, "Gi0/0/1", None),
    (MODULE._canonical_cisco_xe_physical, "Gi1/2/1", None),
])
def test_cisco_interface_names_are_canonical_only_inside_their_ranges(function, value, expected) -> None:
    assert function(value) == expected


def test_only_a_server_issued_continuation_page_is_free() -> None:
    assert Proxy._rate_costs_slot("ssh_read", {"target": ALIAS})
    assert Proxy._rate_costs_slot("ssh_read", {"offset": 0})
    assert not Proxy._rate_costs_slot("ssh_read", {"offset": 1})
    assert not Proxy._rate_costs_slot("schema_read", {"offset": 1})
    assert Proxy._rate_costs_slot("tcp_probe", {"offset": 1})


def test_rate_window_frees_a_slot_exactly_at_its_edge_and_reports_the_wait(monkeypatch) -> None:
    proxy = Proxy()
    clock = iter((100.0, 130.0, 140.0, 160.0, 160.5))
    monkeypatch.setattr(MODULE.time, "monotonic", lambda: next(clock))
    limit = {"requests": 2, "window_seconds": 60}
    proxy._consume_rate_limit(ALIAS, limit)
    proxy._consume_rate_limit(ALIAS, limit)
    with pytest.raises(MODULE.RateLimitError) as refused:
        proxy._consume_rate_limit(ALIAS, limit)
    assert refused.value.data["retry_after_seconds"] == 20
    proxy._consume_rate_limit(ALIAS, limit)
    assert list(proxy.rate_history[ALIAS]) == [130.0, 160.0]
    with pytest.raises(MODULE.RateLimitError) as again:
        proxy._consume_rate_limit(ALIAS, limit)
    assert again.value.data["retry_after_seconds"] == 30


def test_rate_wait_is_at_least_one_second_but_not_more_than_needed(monkeypatch) -> None:
    proxy = Proxy()
    proxy.rate_history[ALIAS] = deque([100.0])
    monkeypatch.setattr(MODULE.time, "monotonic", lambda: 159.5)
    with pytest.raises(MODULE.RateLimitError) as refused:
        proxy._consume_rate_limit(ALIAS, {"requests": 1, "window_seconds": 60})
    assert refused.value.data["retry_after_seconds"] == 1


def _section(**changes) -> SimpleNamespace:
    values = {
        "ssh_platform": "fortios", "platform": "fortinet",
        "enabled_queries": ("system_status",), "read_inventory": {},
        "sftp_roots": ("/safe",),
        "egress": {
            "allow_dns": True, "allow_icmp": True, "tcp_ports": [443, 21],
            "tcp_port_ranges": [(50_000, 50_010)], "udp_ports": [161],
            "udp_port_ranges": [], "tls_server_names": [],
        },
    }
    values.update(changes)
    platform = values.pop("platform")
    return SimpleNamespace(catalog_platform=lambda: platform, **values)


ENTRY = SimpleNamespace(address="192.0.2.10")


@pytest.mark.parametrize(("tool", "args"), [
    ("dns_probe", {}),
    ("icmp_probe", {}),
    ("tls_probe", {}),
    ("ftp_list", {"remote_path": "/safe/file"}),
])
def test_probes_allowed_by_policy_are_authorized_with_their_default_port(tool, args) -> None:
    Proxy._authorize_tool(tool, {"target": ALIAS, **args}, ENTRY, _section())


def test_a_default_port_outside_the_policy_is_refused() -> None:
    section = _section(egress={**_section().egress, "tcp_ports": [444, 22]})
    for tool, args in (("tls_probe", {}), ("ftp_list", {"remote_path": "/safe/file"})):
        with pytest.raises(MODULE.PolicyScopeError):
            Proxy._authorize_tool(tool, {"target": ALIAS, **args}, ENTRY, section)


def test_a_slot_whose_inventory_category_is_missing_is_out_of_scope() -> None:
    section = _section(ssh_platform="arista_eos", platform="arista_eos",
                       enabled_queries=("arp_entry",), read_inventory={})
    args = {"target": ALIAS, "platform": "arista_eos", "query": "arp_entry",
            "parameters": {"address": "192.0.2.1"}}
    with pytest.raises(MODULE.PolicyScopeError):
        Proxy._authorize_tool("ssh_read", args, ENTRY, section)
    section.read_inventory = {"addresses": ("192.0.2.1",)}
    Proxy._authorize_tool("ssh_read", args, ENTRY, section)


def test_a_schema_path_without_enrolled_schema_paths_is_out_of_scope() -> None:
    with pytest.raises(MODULE.PolicyScopeError):
        Proxy._authorize_tool("schema_read", {"target": ALIAS, "path": "system"}, ENTRY, _section())
    section = _section(read_inventory={"schema_paths": ("system",)})
    Proxy._authorize_tool("schema_read", {"target": ALIAS, "path": "system"}, ENTRY, section)


def test_ssh_read_needs_an_ssh_platform_even_with_enabled_queries() -> None:
    section = _section(ssh_platform=None, platform=None)
    with pytest.raises(MODULE.PolicyScopeError):
        Proxy._authorize_tool("ssh_read", {"target": ALIAS, **SSH, "platform": "fortinet"}, ENTRY, section)


def test_session_secrets_skip_empty_and_missing_values() -> None:
    credential = SimpleNamespace(use=lambda: "device-secret")
    assert Proxy._session_secrets(credential, None) == ("device-secret",)
    assert Proxy._session_secrets(credential, {}) == ("device-secret",)
    usm = {"auth_key": "auth-key-x", "priv_key": "priv-key-x"}
    assert Proxy._session_secrets(credential, usm) == ("device-secret", "auth-key-x", "priv-key-x")
    assert Proxy._session_secrets(credential, {**usm, "auth_key": ""}) == ("device-secret", "priv-key-x")
    assert Proxy._session_secrets(credential, {**usm, "priv_key": "auth-key-x"}) == ("device-secret", "auth-key-x")
    assert Proxy._session_secrets(SimpleNamespace(use=lambda: ""), usm) == ("auth-key-x", "priv-key-x")


CONFIG_READ = {"platform": "fortios", "section": "all", "include_all": True}


@pytest.mark.parametrize("tool, extra", [
    ("config_read", CONFIG_READ),
    ("config_read", {**CONFIG_READ, "limit": 48_000}),
    ("config_diff", {"platform": "fortios", "base_snapshot": "cfg_" + "0" * 32, "other_snapshot": "cfg_" + "1" * 32}),
])
def test_a_configuration_page_inside_its_limits_is_accepted(tool, extra) -> None:
    assert _call(tool, extra) == {"target": ALIAS, **extra}


@pytest.mark.parametrize("tool, extra", [
    ("config_read", {**CONFIG_READ, "limit": 0}),
    ("config_read", {**CONFIG_READ, "limit": 48_001}),
    ("config_diff", {"platform": "fortios", "base_snapshot": "cfg_" + "0" * 32,
                     "other_snapshot": "cfg_" + "1" * 32, "offset": -1}),
    ("config_read", {**CONFIG_READ, "redaction": "none"}),
    ("config_read", {**CONFIG_READ, "include_defaults": 1}),
    ("config_read", {**CONFIG_READ, "section": "no-such-section"}),
])
def test_a_configuration_page_or_read_mode_outside_its_contract_is_refused(tool, extra) -> None:
    with pytest.raises(MODULE.ToolArgumentsError):
        _call(tool, extra)


def _snmp_record(**changes) -> SimpleNamespace:
    record = {"kind": MODULE.core_vault.SNMP_KIND, "login": "netops-usm", "auth_protocol": "sha256",
              "priv_protocol": "aes128", "use": lambda: "auth-key-x", "use_priv": lambda: "priv-key-x"}
    record.update(changes)
    return SimpleNamespace(**record)


def _usm(record: SimpleNamespace) -> dict | None:
    owner = SimpleNamespace(_credential=lambda vault, name: record)
    return Proxy._snmp_usm(owner, SimpleNamespace(snmp_credential="usm"), object(), True)


def _no_priv() -> str:
    raise MODULE.core_vault.VaultError("no priv_value")


def test_a_valid_snmp_usm_record_becomes_the_session_usm() -> None:
    assert _usm(_snmp_record()) == {"user": "netops-usm", "auth_protocol": "sha256", "auth_key": "auth-key-x",
                                    "priv_protocol": "aes128", "priv_key": "priv-key-x"}


@pytest.mark.parametrize("changes", [
    {"auth_protocol": "md5"},
    {"use": lambda: "short"},
    {"use_priv": _no_priv},
])
def test_an_unusable_snmp_usm_record_is_refused_as_authentication_material(changes) -> None:
    with pytest.raises(MODULE.AuthenticationMaterialError) as refused:
        _usm(_snmp_record(**changes))
    assert refused.value.__cause__ is None
    assert refused.value.__suppress_context__
