"""CIDR prefixes in lookups and in the sessions/flow filters (U1).

A prefix is accepted only where nothing connects to it (route and policy lookups, the sessions and
flow filters) and only inside an enrolled `lookup_prefixes` entry; egress is not widened.
"""

from __future__ import annotations

from dataclasses import replace
import ipaddress
from types import SimpleNamespace

import pytest

from conftest import _target
from netops_helper import engine, inventory as helper_inventory, proxy as proxy_module
from netops_helper import fortios_diagnostics as diag
from netops_helper.auth import _normalize_inventory
from netops_helper.read_policy import canonical_prefix, enrolled_lookup, render_read_query
from test_fortios_diagnostics import INTERFACE, Shell

PREFIX = "198.51.100.0/24"
INVENTORY = {"addresses": ("192.0.2.20",), "lookup_prefixes": (PREFIX, "2001:db8:20::/48"),
             "flow_ports": ("443",), "ip_protocols": ("6",), "interfaces": ("port1",), "policy_types": ("policy",)}
FLOW = {"src_port": "443", "dst_port": "443", "protocol": "6", "device": "port1", "pol_type": "policy"}

# built at run time: the source privacy gate refuses multicast literals outside its listed exceptions
MULTICAST_PREFIX = str(ipaddress.ip_network((0xEF010000, 16)))

BAD_PREFIXES = [
    "198.51.100.1/24",                    # host bits
    "198.51.100.0/255.255.255.0",         # mask notation
    "198.51.100.0/0.0.0.255",             # wildcard notation
    "198.051.100.0/24", "198.51.100/24",  # non canonical address
    "198.51.100.0/024", "198.51.100.0/+24",
    "0.0.0.0/0", "::/0",                  # not a usable scope
    "198.51.100.0/33", "2001:db8::/129",
    "2001:DB8:20::/48",                   # upper case is not canonical
    "fe80::1%eth0/64", "198.51.100.0%x/24",
    " 198.51.100.0/24", "198.51.100.0/24 ", "198.51.100.0/24\n", "198.51.100.0/24;reload", "198.51.100.0/24 198.51.100.1",
    "198.51.100.0/24/16", "198.51.100.0/", "/16", "198.51.100.0/24\x00", "198.51.100.0/٢٤",
]


def _auth(query="route_lookup", **inventory):
    return replace(_target("fortinet", query), read_inventory={**INVENTORY, **inventory}, enabled_queries=(query,))


# ---- shape of the enrolled value ------------------------------------------------------------

def test_canonical_prefixes_are_accepted_and_returned_as_networks():
    assert str(canonical_prefix(PREFIX, 4)) == PREFIX
    assert str(canonical_prefix("2001:db8:20::/48", 6)) == "2001:db8:20::/48"
    assert str(canonical_prefix("192.0.2.5/32", 4)) == "192.0.2.5/32"
    with pytest.raises(ValueError):
        canonical_prefix(PREFIX, 6)


@pytest.mark.parametrize("value", BAD_PREFIXES)
def test_noncanonical_or_hostile_prefixes_are_refused_everywhere(value):
    for version in (4, 6):
        with pytest.raises(ValueError):
            canonical_prefix(value, version)
    with pytest.raises(helper_inventory.InventoryError):
        helper_inventory._checked_read_inventory("device", {"lookup_prefixes": [value]})
    with pytest.raises(ValueError):
        _normalize_inventory({"lookup_prefixes": [value]})
    assert proxy_module._lookup_network(value, 4) is None and proxy_module._lookup_network(value, 6) is None


def test_inventory_accepts_canonical_prefixes_and_keeps_them_apart_from_addresses():
    clean = helper_inventory._checked_read_inventory(
        "device", {"lookup_prefixes": [PREFIX, "2001:db8:20::/48"], "addresses": ["192.0.2.20"]})
    assert clean["lookup_prefixes"] == (PREFIX, "2001:db8:20::/48")
    with pytest.raises(helper_inventory.InventoryError):  # a prefix is not an address
        helper_inventory._checked_read_inventory("device", {"addresses": [PREFIX]})
    with pytest.raises(helper_inventory.InventoryError):  # an address is not a prefix
        helper_inventory._checked_read_inventory("device", {"lookup_prefixes": ["192.0.2.20"]})
    with pytest.raises(helper_inventory.InventoryError):  # unique
        helper_inventory._checked_read_inventory("device", {"lookup_prefixes": [PREFIX, PREFIX]})


# ---- route_lookup and policy_lookup -----------------------------------------------------------

@pytest.mark.parametrize("value,rendered", [
    ("198.51.100.0/24", "198.51.100.0"),
    ("198.51.100.112/28", "198.51.100.112"),
    ("198.51.100.121/32", "198.51.100.121"),
    ("192.0.2.20", "192.0.2.20"),
])
def test_route_lookup_takes_the_network_address_of_a_prefix(value, rendered):
    assert render_read_query("fortinet", "route_lookup", {"address": value}, INVENTORY) == (
        "fortinet", "get router info routing-table details " + rendered)
    normalized, command, _ = engine._ssh_read_state(_auth(), "fortinet", "route_lookup", {"address": value})
    assert command == "get router info routing-table details " + rendered


@pytest.mark.parametrize("value", [
    "203.0.113.0/24",     # outside the enrolled prefix
    "198.51.100.0/22",    # wider than the enrolled prefix
    "198.51.100.0/23",
    "2001:db8:20::/48",   # wrong family for route_lookup
    "192.0.2.0/24",       # not enrolled at all
    "198.51.100.121",     # an address inside a prefix is still not an enrolled address
    *BAD_PREFIXES,
])
def test_route_lookup_refuses_what_is_not_inside_an_enrolled_prefix(value):
    with pytest.raises(ValueError):
        render_read_query("fortinet", "route_lookup", {"address": value}, INVENTORY)


def test_a_prefix_needs_lookup_prefixes_even_when_addresses_are_enrolled():
    without = {key: value for key, value in INVENTORY.items() if key != "lookup_prefixes"}
    with pytest.raises(ValueError):
        render_read_query("fortinet", "route_lookup", {"address": PREFIX}, without)
    # and lookup_prefixes alone never makes a single address usable
    only = {**without, "addresses": (), "lookup_prefixes": (PREFIX,)}
    with pytest.raises(ValueError):
        render_read_query("fortinet", "route_lookup", {"address": "198.51.100.5"}, only)


def test_policy_lookup_takes_prefixes_in_both_families():
    _, command = render_read_query(
        "fortinet", "policy_lookup_ipv4", {**FLOW, "src_ip": "198.51.100.0/24", "dst_ip": "192.0.2.20"}, INVENTORY)
    assert command == "diagnose firewall iprope lookup 198.51.100.0 443 192.0.2.20 443 6 port1 policy"
    _, command = render_read_query(
        "fortinet", "policy_lookup_ipv6", {**FLOW, "src_ip": "2001:db8:20:1::/64", "dst_ip": "2001:db8:20::/48"}, INVENTORY)
    assert command == "diagnose firewall iprope6 lookup 2001:db8:20:1:: 443 2001:db8:20:: 443 6 port1 policy"
    for name in ("src_ip", "dst_ip"):
        for family, query, outside in ((4, "policy_lookup_ipv4", "203.0.113.0/24"), (6, "policy_lookup_ipv6", "2001:db8:21::/48")):
            good = {"src_ip": "192.0.2.20", "dst_ip": "192.0.2.20"} if family == 4 else {
                "src_ip": "2001:db8:20::1", "dst_ip": "2001:db8:20::1"}
            with pytest.raises(ValueError):
                render_read_query("fortinet", query, {**FLOW, **good, name: outside}, {
                    **INVENTORY, "addresses": ("192.0.2.20", "2001:db8:20::1")})


def test_the_other_vendors_and_peers_keep_taking_single_addresses_only():
    for platform, query, slot in (("cisco_ios", "route_lookup", "address"), ("juniper_junos", "route_lookup", "address"),
                                  ("fortinet", "bgp_received_ipv4", "peer")):
        with pytest.raises(ValueError):
            render_read_query(platform, query, {slot: PREFIX}, INVENTORY)


# ---- the proxy authorises independently of the engine ----------------------------------------------

def _section(**inventory):
    return SimpleNamespace(
        egress={"tcp_port_ranges": [], "tcp_ports": [22], "udp_ports": [], "udp_port_ranges": [],
                "allow_icmp": False, "allow_dns": False, "tls_server_names": []},
        read_inventory={**INVENTORY, **inventory}, ssh_platform="fortios", enabled_queries=("route_lookup", "system_status"),
        catalog_platform=lambda: "fortinet", sftp_roots=[], fortios_output_standard_verified=True)


def _authorize_read(value, **inventory):
    proxy_module.Proxy._authorize_tool(
        "ssh_read", {"platform": "fortinet", "query": "route_lookup", "parameters": {"address": value}},
        SimpleNamespace(port=22), _section(**inventory))


@pytest.mark.parametrize("value", ["198.51.100.0/24", "198.51.100.240/28", "192.0.2.20"])
def test_proxy_authorizes_what_the_engine_renders(value):
    _authorize_read(value)


@pytest.mark.parametrize("value,field", [
    ("203.0.113.0/24", "lookup_prefixes"), ("198.51.100.1/24", "lookup_prefixes"), ("198.51.100.0/22", "lookup_prefixes"),
    ("198.51.100.5", "addresses"), ("192.0.2.0/24", "lookup_prefixes"), ("::/0", "lookup_prefixes"),
])
def test_proxy_refuses_with_the_inventory_field_that_would_grant_it(value, field):
    with pytest.raises(proxy_module.PolicyScopeError) as refusal:
        _authorize_read(value)
    assert refusal.value.data["field"] == field and refusal.value.data["parameter"] == "address"


def test_proxy_and_engine_agree_on_a_corpus():
    corpus = ["198.51.100.0/24", "198.51.100.16/28", "198.51.100.5/32", "203.0.113.0/26", "198.51.100.0/23", "192.0.2.20", "198.51.100.5",
              "2001:db8:20::/48", *BAD_PREFIXES]
    for value in corpus:
        try:
            render_read_query("fortinet", "route_lookup", {"address": value}, INVENTORY)
            engine_ok = True
        except ValueError:
            engine_ok = False
        try:
            _authorize_read(value)
            proxy_ok = True
        except proxy_module.PolicyScopeError:
            proxy_ok = False
        assert engine_ok == proxy_ok, value


# ---- sessions and flow filters -------------------------------------------------------------------

DIAG_INVENTORY = {"diagnostic_recipes": ("sessions", "flow", "ping", "sniffer"), "interfaces": (INTERFACE,),
                  "addresses": ("192.0.2.183",), "lookup_prefixes": (PREFIX,)}


class DiagAuth:
    fortios_output_standard_verified = True
    read_inventory = DIAG_INVENTORY

    def require_ssh_query(self, platform, query):
        assert (platform, query) == ("fortinet", "system_status")


def _validate(recipe, address, **tuple_values):
    diag.validate(recipe, address, INTERFACE, 2, 1, 1000, **tuple_values)


@pytest.mark.parametrize("recipe", ["sessions", "flow"])
def test_the_filter_recipes_take_a_prefix_inside_an_enrolled_prefix(recipe):
    _validate(recipe, PREFIX)
    diag.authorize(DiagAuth(), recipe, PREFIX, INTERFACE)
    diag.authorize(DiagAuth(), recipe, "198.51.100.112/28", INTERFACE, source_address="198.51.100.128/28")
    for outside in ("203.0.113.0/24", "198.51.100.0/22", "198.51.100.5"):
        with pytest.raises(ValueError):
            diag.authorize(DiagAuth(), recipe, outside, INTERFACE)
    with pytest.raises(ValueError):
        diag.authorize(DiagAuth(), recipe, PREFIX, INTERFACE, source_address="203.0.113.0/26")


@pytest.mark.parametrize("recipe", ["ping", "traceroute", "sniffer", "logs"])
def test_recipes_that_connect_or_capture_never_take_a_prefix(recipe):
    with pytest.raises(ValueError):
        _validate(recipe, PREFIX)
    with pytest.raises(ValueError):
        proxy_module.Proxy._validate_tool_arguments("fortios_diagnostics", {
            "target": "fixture", "recipe": recipe, "address": PREFIX, "interface": INTERFACE})


@pytest.mark.parametrize("value", [v for v in BAD_PREFIXES if v not in ("0.0.0.0/0",)] + [
    "224.0.0.0/4", "0.0.0.0/8", "255.255.255.0/24", MULTICAST_PREFIX, "198.51.100.0/24 198.51.100.17",
    "198.51.100.0/24;diagnose sys kill 11 1", "::/0", "2001:db8::/32",
])
@pytest.mark.parametrize("recipe", ["sessions", "flow"])
def test_hostile_filter_prefixes_are_refused_in_the_engine_and_the_proxy(recipe, value):
    with pytest.raises(ValueError):
        _validate(recipe, value)
    with pytest.raises(proxy_module.ToolArgumentsError):
        proxy_module.Proxy._validate_tool_arguments("fortios_diagnostics", {
            "target": "fixture", "recipe": recipe, "address": value, "interface": INTERFACE})


def test_the_proxy_validates_and_authorizes_filter_prefixes():
    request = {"target": "fixture", "recipe": "sessions", "address": PREFIX, "interface": INTERFACE}
    assert proxy_module.Proxy._validate_tool_arguments("fortios_diagnostics", dict(request))["address"] == PREFIX
    tuple_request = {**request, "recipe": "flow", "source_address": "198.51.100.128/28", "source_port": 1024,
                     "destination_port": 443, "protocol": 6}
    assert proxy_module.Proxy._validate_tool_arguments("fortios_diagnostics", dict(tuple_request))["source_address"]
    bad_source = {**tuple_request, "source_address": "198.51.100.129/28"}
    with pytest.raises(proxy_module.ToolArgumentsError):
        proxy_module.Proxy._validate_tool_arguments("fortios_diagnostics", bad_source)
    section = _section(**DIAG_INVENTORY)
    entry = SimpleNamespace(port=22)
    section.enabled_queries = ("system_status",)
    for good in (request, tuple_request):
        proxy_module.Proxy._authorize_tool("fortios_diagnostics", good, entry, section)
    for field, mutated in (("lookup_prefixes", {**request, "address": "203.0.113.0/24"}),
                           ("lookup_prefixes", {**tuple_request, "source_address": "203.0.113.0/26"}),
                           ("addresses", {**request, "address": "198.51.100.5"})):
        with pytest.raises(proxy_module.PolicyScopeError) as refusal:
            proxy_module.Proxy._authorize_tool("fortios_diagnostics", mutated, entry, section)
        assert refusal.value.data["field"] == field


class GrammarShell(Shell):
    """Enforce operand counts and retain both range ends instead of the last token."""
    def __init__(self, recipe, *, ranges=True, refuse=False):
        super().__init__(recipe)
        self.status_line = "Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)"
        self.ranges, self.refuse = ranges, refuse
        self.applied = {}

    def command(self, command, timeout=10):
        for prefix in ("diagnose sys session filter ", "diagnose debug flow filter "):
            if command.startswith(prefix):
                tokens = command[len(prefix):].split()
                if tokens[0] in {"src", "dst", "addr", "saddr", "daddr"}:
                    if len(tokens) != (3 if self.ranges else 2) or self.refuse:
                        self.commands.append(command)
                        raise diag.StepRefused("command parse error\nCommand fail. Return code -61")
                    self.applied[tokens[0]] = tuple(tokens[1:])
        result = super().command(command, timeout)
        # Readback must preserve both endpoints until clear restores the baseline.
        for selector, ends in self.applied.items():
            if selector == "src" and command.startswith("diagnose sys session filter src "):
                self.filter_values["source ip"] = "-".join(ends)
            if selector == "dst" and command.startswith("diagnose sys session filter dst "):
                self.filter = "-".join(ends)
            if selector == "addr" and command.startswith("diagnose debug flow filter addr "):
                self.filter = "-".join(ends)
        return result


@pytest.mark.parametrize("recipe", ["sessions", "flow"])
def test_measured_80f_range_commands_have_no_refusal(recipe):
    from pathlib import Path
    transcript = (Path(__file__).parent / "fixtures/fortios_80f_range_probe.txt").read_text()
    prefix = "diagnose sys session filter src" if recipe == "sessions" else "diagnose debug flow filter addr"
    assert prefix + " 192.0.2.1 192.0.2.2" in transcript
    assert prefix.rsplit(" ", 1)[0] + " clear" in transcript
    assert not diag.REFUSAL.search(transcript)
    assert not engine._cli_refused("fortinet", transcript)
    assert ("FortiGate-80F", "8.0.2", "0251") in diag.PREFIX_RANGE_IDENTITIES


@pytest.mark.parametrize("recipe", ["sessions", "flow"])
@pytest.mark.parametrize("with_tuple", [True, False])
def test_80f_filter_preserves_both_prefix_ends_and_cleans_up(recipe, with_tuple):
    shell = GrammarShell(recipe)
    options = dict(source_address="198.51.100.128/28", source_port=49152, destination_port=443, protocol=6) if with_tuple else {}
    diag.run(shell, recipe, PREFIX, INTERFACE, 2, 1, **options)
    dest = "dst" if recipe == "sessions" else "daddr" if with_tuple else "addr"
    assert shell.applied[dest] == ("198.51.100.0", "198.51.100.255")
    if with_tuple:
        assert shell.applied["src" if recipe == "sessions" else "saddr"] == ("198.51.100.128", "198.51.100.143")
    assert shell.filter == "any" and not shell.enabled
    state = shell.filter_values if recipe == "sessions" else shell.flow_values
    fields = diag.SESSION_FIELDS if recipe == "sessions" else diag.FLOW_FIELDS
    assert state == {field: "any" for field in fields}


@pytest.mark.parametrize("recipe", ["sessions", "flow"])
def test_existing_60f_tuple_range_grammar_keeps_prefix_support(recipe):
    shell = GrammarShell(recipe)
    shell.status_line = "Version: FortiGate-60F v7.6.8,build3744,240101"
    diag.run(shell, recipe, PREFIX, INTERFACE, 2, 1, source_address="198.51.100.128/28",
             source_port=49152, destination_port=443, protocol=6)
    assert shell.applied["src" if recipe == "sessions" else "saddr"] == ("198.51.100.128", "198.51.100.143")
    assert shell.applied["dst" if recipe == "sessions" else "daddr"] == ("198.51.100.0", "198.51.100.255")
    assert not shell.enabled and shell.filter == "any"


@pytest.mark.parametrize("recipe", ["sessions", "flow"])
@pytest.mark.parametrize("prefix_field", ["address", "source_address"])
@pytest.mark.parametrize("identity", sorted(diag.IDENTITIES - diag.PREFIX_RANGE_IDENTITIES) + [("FortiGate-80F", "8.0.2", "0250")])
def test_unmeasured_prefix_is_refused_before_diagnostic_state_changes(recipe, prefix_field, identity):
    shell = GrammarShell(recipe, ranges=False)
    shell.status_line = "Version: %s v%s,build%s,240101" % identity
    options = dict(source_address="192.0.2.184", source_port=1024, destination_port=443, protocol=6)
    address = PREFIX if prefix_field == "address" else "192.0.2.183"
    if prefix_field == "source_address":
        options["source_address"] = PREFIX
    with pytest.raises(diag.OptionRefused, match="prefix_not_supported_on_identity"):
        diag.run(shell, recipe, address, INTERFACE, 2, 1, **options)
    assert shell.commands == ["get system status"]
    assert not shell.enabled and shell.filter == "any"


@pytest.mark.parametrize("recipe", ["sessions", "flow"])
def test_a_rejected_range_is_cleaned_up_without_listing_or_enabling_debug(recipe):
    shell = GrammarShell(recipe, refuse=True)
    with pytest.raises(diag.StepRefused):
        diag.run(shell, recipe, PREFIX, INTERFACE, 2, 1)
    assert any(command.endswith("filter clear") for command in shell.commands)
    assert "diagnose sys session list" not in shell.commands
    assert "diagnose debug enable" not in shell.commands
    assert not any(command.startswith("diagnose debug flow trace start") for command in shell.commands)
    assert not shell.enabled and shell.filter == "any"


def test_flow_filter_summary_includes_both_prefix_ends():
    assert diag.flow_filter(PREFIX) == "addr 198.51.100.0 198.51.100.255 proto 1"
    assert diag.flow_filter("198.51.100.112/28", "198.51.100.128/28", 1024, 443, 6) == (
        "saddr 198.51.100.128 198.51.100.143 sport 1024 daddr 198.51.100.112 198.51.100.127 dport 443 proto 6")
    assert diag.flow_filter("192.0.2.183") == "addr 192.0.2.183 proto 1"


def test_a_single_address_keeps_its_exact_commands():
    shell = Shell("sessions")
    diag.run(shell, "sessions", "192.0.2.183", INTERFACE, 2, 1)
    assert "diagnose sys session filter dst 192.0.2.183" in shell.commands


def test_the_audit_summary_records_a_canonical_prefix_and_nothing_else():
    fields = engine._audit_fields({"recipe": "sessions", "address": PREFIX, "source_address": "198.51.100.128/28"}, {})
    assert fields["destination_address"] == PREFIX and fields["source_address"] == "198.51.100.128/28"
    for hostile in ("198.51.100.1/24", "198.51.100.0/24;x", "224.0.0.0/4", "0.0.0.0/8", "198.51.100.0/255.255.255.0"):
        assert "destination_address" not in engine._audit_fields({"recipe": "sessions", "address": hostile}, {})


def test_egress_is_not_widened_by_lookup_prefixes():
    inventory = helper_inventory._checked_read_inventory("device", {"lookup_prefixes": [PREFIX]})
    assert inventory == {"lookup_prefixes": (PREFIX,)}
    auth = _auth()
    assert not auth.egress.allows_address("198.51.100.5")
