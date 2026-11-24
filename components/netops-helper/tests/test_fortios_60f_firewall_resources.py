"""FIREWALL-RESOURCES (1.0.12): log category filters, session filters by client, port and policy, and host/port/ARP sniffer filters,
measured on the lab FortiGate-60F 7.6.8 build 3744 (FP-01, FP-05, FP-06).

The fixture holds the bytes a read-only account received from the lab 60F for exactly the commands these recipes
send (verification, anonymised; see its "source"); each member is one SSH session. The fake session answers each sent
command with the recorded bytes (later answers of a repeated command in order), so the real diagnostic shell, the
real recipe and its restore checks run unchanged.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import json
import pathlib
from types import SimpleNamespace

import pytest

from netops_helper import engine
from netops_helper import fortios_diagnostics as d
from netops_helper import proxy
from test_error_branches_helper_engine import _OpenSession, _assert_audit, _diagnostic_target, audit_log  # noqa: F401

RECORDED = json.loads(pathlib.Path(__file__).with_name("fixtures").joinpath("firewall_resources_fortios_60f_768.json").read_text())
INTERFACE = "wan1"
CLIENT = "192.0.2.20"          # a lab VM behind the 60F that sent the traffic during the capture
PUBLIC = "203.0.113.253"       # the public DNS/HTTPS server it used
SIXTY_F = ("FortiGate-60F", "7.6.8", "3744")
OTHER = ("FortiGate-80F", "8.0.2", "0251")


class _Replay:
    """One recorded SSH session: a command answers its recorded bytes; later answers of it follow in order."""

    def __init__(self, member: str, patch=None) -> None:
        recorded = RECORDED["members"][member]
        self.responses = {command: [answer] + recorded.get("repeats", {}).get(command, [])
                          for command, answer in recorded["responses"].items()}
        if patch:
            patch(self.responses)
        self.pending = [recorded["login"].encode("latin-1")]
        self.sent: list[str] = []

    def expect(self, patterns, timeout):
        buffer = self.pending.pop(0)
        position, index = min((buffer.find(p), i) for i, p in enumerate(patterns) if p in buffer)
        return index, buffer[: position + len(patterns[index])]

    def discard(self, seen) -> None:
        pass

    def send(self, line) -> None:
        self.sent.append(line)
        answers = self.responses[line]
        self.pending.append((answers.pop(0) if len(answers) > 1 else answers[0]).encode("latin-1"))

    def interrupt(self) -> None:
        pass

    def close(self) -> None:
        pass


def _shell(member: str, patch=None):
    session = _Replay(member, patch)
    return session, engine._FortiosDiagnosticShell(session)


def _fresh():
    fresh = _Replay("fresh")

    @contextmanager
    def reconnect():
        yield engine._FortiosDiagnosticShell(fresh)

    return fresh, reconnect


# --- FP-01: logs of a category, subtype, client and action ----------------------------------------------------------

def test_event_system_logs_set_a_session_filter_and_a_new_session_verifies_it() -> None:
    session, shell = _shell("logs_system")
    fresh, reconnect = _fresh()
    support = []
    result, timed_out, identity, domain = d.run(shell, "logs", "", INTERFACE, 3, 10, reconnect=reconnect,
                                                support=support, log_category="event", log_subtype="system")
    assert session.sent[3:9] == ["execute log filter dump", "execute log filter category event",
                                 "execute log filter field subtype system", "execute log filter view-lines 5",
                                 "execute log filter dump", "execute log display"]
    assert result["state"] == "ok" and (result["found"], result["loaded"], result["returned"]) == (130, 5, 3)
    assert result["searched_percent"] == 4.0 and result["truncated"] is True
    assert result["filter"]["category"] == "event" and result["filter"]["Filter"] == '( subtype "system" )'
    assert result["output"].count('subtype="system"') == 3 and 'logdesc="Admin login successful"' in result["output"]
    assert fresh.sent == ["get system status", "execute log filter dump"]
    assert not timed_out and identity == SIXTY_F and domain == "root"
    assert support[0]["status"] == "tested" and support[0]["message"] is None


@pytest.mark.parametrize("member, subtype, found", [("logs_vpn", "vpn", 2), ("logs_user", "user", 3)])
def test_event_logs_searched_completely_report_no_search_percentage(member, subtype, found) -> None:
    session, shell = _shell(member)
    fresh, reconnect = _fresh()
    result = d.run(shell, "logs", "", INTERFACE, 3, 10, reconnect=reconnect, log_category="event",
                   log_subtype=subtype)[0]
    assert "execute log filter view-lines 5" in session.sent  # view-lines takes 5-1000 (measured)
    assert result["state"] == "ok" and result["found"] == result["loaded"] == found
    assert result["returned"] == min(found, 3) and result["searched_percent"] is None


def test_traffic_logs_of_one_client_filter_srcip_on_the_device() -> None:
    session, shell = _shell("logs_traffic_src")
    fresh, reconnect = _fresh()
    result = d.run(shell, "logs", CLIENT, INTERFACE, 3, 10, reconnect=reconnect, log_category="traffic")[0]
    assert "execute log filter field srcip " + CLIENT in session.sent
    assert result["state"] == "ok" and (result["found"], result["loaded"], result["matched"]) == (424, 5, 5)
    assert result["returned"] == 3 and result["output"].count("srcip=" + CLIENT + " ") == 3
    assert result["searched_percent"] == 13.2


def test_denied_traffic_of_a_client_with_nothing_found_in_a_partial_search_is_incomplete() -> None:
    # Measured: the 60F had no denied traffic in memory; 0 found at 30.6 % searched is not an empty log.
    session, shell = _shell("logs_deny")
    fresh, reconnect = _fresh()
    result = d.run(shell, "logs", CLIENT, INTERFACE, 3, 10, reconnect=reconnect, log_category="traffic",
                   log_action="deny")[0]
    assert session.sent[4:7] == ["execute log filter category traffic", "execute log filter field srcip " + CLIENT,
                                 "execute log filter field action deny"]
    assert result["filter"]["Filter"] == '( action "deny" ) AND ( srcip "' + CLIENT + '" )'
    assert result["state"] == "incomplete" and result["found"] == 0 and result["searched_percent"] == 30.6


def test_logs_with_a_category_are_unverified_without_a_new_session() -> None:
    session, shell = _shell("logs_system")
    with pytest.raises(d.RestoreUnverified):
        d.run(shell, "logs", "", INTERFACE, 3, 10, log_category="event", log_subtype="system")


def test_a_filter_the_device_does_not_show_is_refused_before_the_display() -> None:
    def lost_field(responses):
        dump = responses["execute log filter dump"]
        dump[1] = dump[1].replace('Filter: ( subtype "system" )', "Filter: ")

    session, shell = _shell("logs_system", lost_field)
    fresh, reconnect = _fresh()
    with pytest.raises(ValueError, match="did not show the requested log filter"):
        d.run(shell, "logs", "", INTERFACE, 3, 10, reconnect=reconnect, log_category="event", log_subtype="system")
    assert "execute log display" not in session.sent and fresh.sent[-1] == "execute log filter dump"


# --- FP-05: the sessions of a client, by destination port and policy -------------------------------------------------

def test_sessions_of_a_client_to_a_port_through_a_policy() -> None:
    session, shell = _shell("sessions_client")
    support = []
    output, timed_out, identity, domain = d.run(shell, "sessions", "", INTERFACE, 8, 10, support=support,
                                                source_address=CLIENT, destination_port=443, policy_id=5)
    assert session.sent[4:7] == ["diagnose sys session filter src " + CLIENT + " " + CLIENT,
                                 "diagnose sys session filter dport 443 443", "diagnose sys session filter policy 5 5"]
    assert "diagnose sys session filter proto 1" not in session.sent
    assert session.sent[-2:] == ["diagnose sys session filter clear", "diagnose sys session filter"]
    text, complete, omitted = d.session_projection(output.replace("\r", ""), 8)
    assert complete and omitted == 0 and "policy_id=5 " in text and "total session: 1" in text
    assert "hook=post dir=org act=snat " + CLIENT + ":47886->" in text
    assert support[0]["status"] == "tested"


def test_all_sessions_of_a_client_include_its_local_sessions() -> None:
    session, shell = _shell("sessions_src")
    output = d.run(shell, "sessions", "", INTERFACE, 8, 10, source_address=CLIENT)[0]
    text, complete, omitted = d.session_projection(output.replace("\r", ""), 8)
    assert complete and text.count("session proto=") >= 4
    assert "policy_id=4294967295" in text and "policy_id=5" in text and "proto=17" in text and "proto=6" in text


def test_a_session_filter_the_device_does_not_show_is_refused_and_cleared() -> None:
    def ignored_policy(responses):
        shown = responses["diagnose sys session filter"]
        shown[1] = shown[1].replace("policy id: 5-5", "policy id: any")

    session, shell = _shell("sessions_client", ignored_policy)
    with pytest.raises(ValueError, match="did not show the requested session filter"):
        d.run(shell, "sessions", "", INTERFACE, 8, 10, source_address=CLIENT, destination_port=443, policy_id=5)
    assert "diagnose sys session list" not in session.sent and "diagnose sys session filter clear" in session.sent


# --- FP-06: host, port and ARP sniffer filters ----------------------------------------------------------------------

@pytest.mark.parametrize("member, address, interface, kwargs, first", [
    ("sniffer_host", PUBLIC, INTERFACE, {"sniffer_filter": "host"}, "wan1 -- 203.0.113.100.52004 -> " + PUBLIC + ".443: syn"),
    ("sniffer_host_port", PUBLIC, INTERFACE, {"sniffer_filter": "port", "destination_port": 53, "protocol": 17},
     "wan1 -- 203.0.113.100.41005 -> " + PUBLIC + ".53: udp 60"),
    ("sniffer_ike", "", INTERFACE, {"sniffer_filter": "port", "destination_port": 500, "protocol": 17},
     "0 packets received by filter"),
    ("sniffer_any_arp", "", "any", {"sniffer_filter": "arp"}, "PVE-MGMT in arp who-has 192.0.2.45"),
])
def test_sniffer_filters_on_the_60f(member, address, interface, kwargs, first) -> None:
    session, shell = _shell(member)
    support = []
    output, timed_out, identity, domain = d.run(shell, "sniffer", address, interface, 3, 10, support=support, **kwargs)
    assert session.sent[-1] == next(command for command in RECORDED["members"][member]["responses"]
                                    if command.startswith("diagnose sniffer packet"))
    assert first in output and support[0]["status"] == "tested"
    if interface == "any":  # no owner of the interface any to verify
        assert session.sent == ["get system status", session.sent[-1]]


def test_the_sniffer_on_any_is_refused_with_vdoms() -> None:
    def multi(responses):
        responses["get system status"] = [responses["get system status"][0].replace(
            "Virtual domain configuration: disable", "Virtual domain configuration: multiple")]

    session, shell = _shell("sniffer_any_arp", multi)
    with pytest.raises(d.ScopeRefused, match="interface any is available only without VDOMs"):
        d.run(shell, "sniffer", "", "any", 3, 10, vdom="root", sniffer_filter="arp")
    assert session.sent == ["get system status"]


@pytest.mark.parametrize("address, kwargs, selector", [
    (PUBLIC, {"sniffer_filter": "host"}, "host " + PUBLIC),
    (PUBLIC, {"sniffer_filter": "port", "destination_port": 443}, "host " + PUBLIC + " and port 443"),
    (PUBLIC, {"sniffer_filter": "port", "destination_port": 22, "protocol": 6}, "host " + PUBLIC + " and tcp port 22"),
    ("", {"sniffer_filter": "port", "destination_port": 4500, "protocol": 17}, "udp port 4500"),
    (PUBLIC, {"sniffer_filter": "arp"}, "arp and host " + PUBLIC),
    ("", {"sniffer_filter": "arp"}, "arp"),
])
def test_sniffer_selectors(address, kwargs, selector) -> None:
    assert d.sniffer_selector(address, kwargs["sniffer_filter"], kwargs.get("destination_port"),
                              kwargs.get("protocol")) == selector


# --- validation, scope and firmware support -------------------------------------------------------------------------

@pytest.mark.parametrize("recipe, address, interface, kwargs", [
    ("logs", "", INTERFACE, {"log_category": "event", "log_subtype": "ha"}),
    ("logs", CLIENT, INTERFACE, {"log_category": "traffic", "log_action": "deny"}),
    ("logs", "", INTERFACE, {"log_category": "utm-ips"}),
    ("sessions", "", INTERFACE, {"source_address": CLIENT}),
    ("sessions", "", INTERFACE, {"source_address": "192.0.2.0/24", "destination_port": 53}),
    ("sessions", PUBLIC, INTERFACE, {"policy_id": 5}),
    ("sessions", PUBLIC, INTERFACE, {"destination_port": 443}),
    ("sniffer", PUBLIC, "any", {"sniffer_filter": "host"}),
    ("sniffer", "", INTERFACE, {"sniffer_filter": "port", "destination_port": 500}),
    ("sniffer", PUBLIC, INTERFACE, {"sniffer_filter": "icmp"}),
])
def test_valid_firewall_resources_requests(recipe, address, interface, kwargs) -> None:
    d.validate(recipe, address, interface, 3, 10, 16000, **kwargs)


@pytest.mark.parametrize("recipe, address, interface, kwargs", [
    ("logs", "", INTERFACE, {}),                                                   # no address without a category
    ("logs", "", INTERFACE, {"log_category": "debug"}),
    ("logs", "", INTERFACE, {"log_subtype": "system"}),
    ("logs", "", INTERFACE, {"log_category": "traffic", "log_subtype": "system"}),
    ("logs", "", INTERFACE, {"log_category": "event", "log_action": "deny"}),
    ("logs", "", INTERFACE, {"log_category": "event", "log_subtype": "system foo"}),
    ("ping", PUBLIC, INTERFACE, {"log_category": "event"}),
    ("sessions", "", INTERFACE, {"destination_port": 443}),                       # no address and no client
    ("sessions", "", INTERFACE, {"policy_id": 5}),
    ("sessions", PUBLIC, INTERFACE, {"policy_id": 0}),
    ("sessions", PUBLIC, INTERFACE, {"policy_id": "5"}),
    ("sessions", PUBLIC, INTERFACE, {"destination_port": 0}),
    ("sniffer", PUBLIC, INTERFACE, {"policy_id": 5}),
    ("sniffer", "", INTERFACE, {"sniffer_filter": "host"}),
    ("sniffer", "", "any", {"sniffer_filter": "port", "destination_port": 500}),   # any needs a host but for arp
    ("ping", PUBLIC, "any", {}),
    ("sniffer", PUBLIC, INTERFACE, {"sniffer_filter": "port"}),
    ("sniffer", PUBLIC, INTERFACE, {"sniffer_filter": "port", "destination_port": 53, "protocol": 1}),
    ("sniffer", PUBLIC, INTERFACE, {"sniffer_filter": "host", "destination_port": 53}),
    ("sniffer", PUBLIC, INTERFACE, {"sniffer_filter": "host", "source_address": CLIENT}),
    ("sniffer", PUBLIC, INTERFACE, {"sniffer_filter": "tcpdump"}),
])
def test_invalid_firewall_resources_requests(recipe, address, interface, kwargs) -> None:
    with pytest.raises(ValueError):
        d.validate(recipe, address, interface, 3, 10, 16000, **kwargs)


class _Auth:
    fortios_output_standard_verified = True

    def __init__(self, **inventory):
        self.read_inventory = {"diagnostic_recipes": ("logs", "sessions", "sniffer"), "interfaces": (INTERFACE,),
                               **inventory}

    def require_ssh_query(self, platform, query):
        assert (platform, query) == ("fortinet", "system_status")


def test_scope_of_an_empty_address_and_of_the_interface_any() -> None:
    d.authorize(_Auth(), "logs", "", INTERFACE)
    d.authorize(_Auth(addresses=(CLIENT,)), "sessions", "", INTERFACE, source_address=CLIENT)
    d.authorize(_Auth(addresses=(PUBLIC,), interfaces=(INTERFACE, "any")), "sniffer", PUBLIC, "any")
    d.authorize(_Auth(interfaces=(INTERFACE, "any")), "sniffer", "", "any")
    for recipe, address, interface, source in (("sessions", "", INTERFACE, CLIENT), ("sniffer", PUBLIC, "any", None),
                                               ("sessions", PUBLIC, "any", None)):
        with pytest.raises(ValueError, match="^diagnostic scope is not enrolled for this target$"):
            d.authorize(_Auth(), recipe, address, interface, source_address=source)
    with pytest.raises(ValueError, match="^diagnostic scope is not enrolled for this target$"):
        d.authorize(_Auth(addresses=(PUBLIC,), interfaces=(INTERFACE, "any")), "sessions", PUBLIC, "any")


@pytest.mark.parametrize("recipe, kwargs, part", [
    ("logs", {"log_category": "event"}, "a log category filter"),
    ("sessions", {"partial": True}, "a session filter by source, destination port or policy"),
    ("sniffer", {"sniffer_filter": "arp"}, "a host, port or ARP sniffer filter or the interface any"),
])
def test_another_identity_runs_the_firewall_resources_parts_with_an_untested_warning(recipe, kwargs, part) -> None:
    named = d.filter_part(recipe, INTERFACE, **kwargs)
    assert named == part
    assert d.firmware_support(SIXTY_F, recipe, filter_part=named)["status"] == "tested"
    other = d.firmware_support(OTHER, recipe, filter_part=named)
    assert other["status"] == "untested" and part in other["message"]
    assert d.filter_part("sniffer", INTERFACE, sniffer_filter="icmp") is None
    assert d.filter_part("sniffer", "any") is not None


def _proxy_call(**extra):
    return proxy.Proxy._validate_tool_arguments("fortios_diagnostics", {"target": "lab-60f", "interface": INTERFACE,
                                                                        **extra})


@pytest.mark.parametrize("extra", [
    {"recipe": "logs", "address": "", "log_category": "event", "log_subtype": "system"},
    {"recipe": "logs", "address": CLIENT, "log_category": "traffic", "log_action": "deny"},
    {"recipe": "sessions", "address": "", "source_address": CLIENT, "destination_port": 443, "policy_id": 5},
    {"recipe": "sessions", "address": PUBLIC, "policy_id": 5},
    {"recipe": "sniffer", "address": "", "sniffer_filter": "port", "destination_port": 500, "protocol": 17},
    {"recipe": "sniffer", "address": PUBLIC, "sniffer_filter": "host", "interface": "any"},
    {"recipe": "sniffer", "address": "", "sniffer_filter": "arp", "interface": "any"},
])
def test_proxy_accepts_the_firewall_resources_arguments(extra) -> None:
    assert _proxy_call(**extra)["recipe"] == extra["recipe"]


@pytest.mark.parametrize("extra", [
    {"recipe": "logs", "address": ""},
    {"recipe": "logs", "address": "", "log_category": "event", "log_action": "deny"},
    {"recipe": "ping", "address": PUBLIC, "log_category": "event"},
    {"recipe": "sessions", "address": "", "destination_port": 443},
    {"recipe": "sessions", "address": PUBLIC, "policy_id": 0},
    {"recipe": "sniffer", "address": "", "sniffer_filter": "host"},
    {"recipe": "sniffer", "address": "", "sniffer_filter": "port", "destination_port": 500, "interface": "any"},
    {"recipe": "sniffer", "address": PUBLIC, "sniffer_filter": "port", "destination_port": 53, "protocol": 1},
    {"recipe": "ping", "address": PUBLIC, "interface": "any"},
    {"recipe": "ping", "address": PUBLIC, "interface": "", "policy_id": 5},
])
def test_proxy_refuses_other_firewall_resources_arguments(extra) -> None:
    with pytest.raises(proxy.ToolArgumentsError):
        _proxy_call(**extra)


def test_proxy_scope_of_an_empty_address_and_the_interface_any() -> None:
    inventory = {"diagnostic_recipes": ("logs", "sessions", "sniffer"), "interfaces": (INTERFACE, "any"),
                 "addresses": (CLIENT,)}
    section = SimpleNamespace(egress={}, catalog_platform=lambda: "fortinet", enabled_queries=("system_status",),
                              read_inventory=inventory)
    allowed = ({"recipe": "logs", "address": "", "interface": INTERFACE, "log_category": "event"},
               {"recipe": "sessions", "address": "", "interface": INTERFACE, "source_address": CLIENT},
               {"recipe": "sniffer", "address": CLIENT, "interface": "any", "sniffer_filter": "host"},
               {"recipe": "sniffer", "address": "", "interface": "any", "sniffer_filter": "arp"})
    for request in allowed:
        proxy.Proxy._authorize_tool("fortios_diagnostics", {"target": "lab-60f", **request}, None, section)
    for request in ({"recipe": "sessions", "address": "", "interface": INTERFACE, "source_address": PUBLIC},
                    {"recipe": "sniffer", "address": PUBLIC, "interface": "any", "sniffer_filter": "host"},
                    {"recipe": "logs", "address": "", "interface": "any", "log_category": "event"}):
        with pytest.raises(proxy.PolicyScopeError):
            proxy.Proxy._authorize_tool("fortios_diagnostics", {"target": "lab-60f", **request}, None, section)


# --- the engine answer ----------------------------------------------------------------------------------------------

def _engine_target(**inventory):
    target = _diagnostic_target()
    return replace(target, read_inventory={**target.read_inventory, "interfaces": (INTERFACE,), **inventory})


class _ClosableSession(_OpenSession):
    def close(self) -> None:  # the logs filter is local to the session
        pass


def test_the_engine_answers_event_logs_with_the_filter_it_set(wire, audit_log, monkeypatch) -> None:
    session, shell = _shell("logs_system")
    fresh = _Replay("fresh")
    shells = iter([shell, engine._FortiosDiagnosticShell(fresh)])
    monkeypatch.setattr(engine.core_session, "fortinet_session", _ClosableSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: next(shells))
    result = engine.fortios_diagnostics(_engine_target(diagnostic_recipes=("logs",)), "logs", "", INTERFACE, 3, 10,
                                        16000, log_category="event", log_subtype="system")
    assert result["ok"] is True and result["log_state"] == "ok" and result["cleanup"] == "verified"
    assert result["filter_applied"]["category"] == "event" and result["searched_percent"] == 4.0
    assert result["filter_source"].startswith("set by this call in its own SSH session")
    assert (result["found"], result["loaded"], result["returned"]) == (130, 5, 3)
    assert result["firmware_support"]["status"] == "tested" and "warnings" not in result
    assert fresh.sent == []
    _assert_audit(audit_log, "fortios_diagnostics", ["started", "ok"])


def test_the_engine_answers_the_sessions_of_a_client(wire, audit_log, monkeypatch) -> None:
    session, shell = _shell("sessions_client")
    monkeypatch.setattr(engine.core_session, "fortinet_session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    result = engine.fortios_diagnostics(_engine_target(diagnostic_recipes=("sessions",), addresses=(CLIENT,)),
                                        "sessions", "", INTERFACE, 8, 10, 16000, source_address=CLIENT,
                                        destination_port=443, policy_id=5)
    assert result["ok"] is True and result["complete"] is True and result["cleanup"] == "verified"
    assert "policy_id=5 " in result["untrusted_device_output"]
    assert result["firmware_support"]["status"] == "tested" and "warnings" not in result
    _assert_audit(audit_log, "fortios_diagnostics", ["started", "ok"])


def test_the_engine_refuses_firewall_resources_filters_for_fortiadc(wire, audit_log) -> None:
    target = replace(_diagnostic_target(), ssh_platform="fortiadc")
    with pytest.raises(ValueError, match="apply only to a FortiOS target"):
        engine.fortios_diagnostics(target, "ping", PUBLIC, "", 3, 10, 16000, policy_id=5)


# --- review: blocking findings 1-4 (verification) ----------------------------------------------------------

def _sniffer_any(monkeypatch, interfaces, **inventory):
    session, shell = _shell("sniffer_any_arp")
    monkeypatch.setattr(engine.core_session, "fortinet_session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    return session, _engine_target(diagnostic_recipes=("sniffer",), interfaces=interfaces, **inventory)


@pytest.mark.parametrize("address, kwargs", [("", {"sniffer_filter": "arp"}),
                                             (PUBLIC, {"sniffer_filter": "host"})])
def test_finding_1_the_sniffer_on_any_is_refused_unless_any_is_enrolled(wire, audit_log, monkeypatch, address,
                                                                        kwargs) -> None:
    # Review finding 1: only wan1 enrolled, yet `any "arp"` (no address) ran across every interface.
    session, target = _sniffer_any(monkeypatch, (INTERFACE,), addresses=(PUBLIC,))
    with pytest.raises(ValueError, match="^diagnostic scope is not enrolled for this target$"):
        engine.fortios_diagnostics(target, "sniffer", address, "any", 3, 10, 16000, **kwargs)
    assert session.sent == []


def test_finding_1_the_sniffer_on_an_enrolled_any_runs_arp(wire, audit_log, monkeypatch) -> None:
    session, target = _sniffer_any(monkeypatch, (INTERFACE, "any"))
    result = engine.fortios_diagnostics(target, "sniffer", "", "any", 3, 10, 16000, sniffer_filter="arp")
    assert result["ok"] is True and "PVE-MGMT in arp who-has" in result["untrusted_device_output"]
    assert session.sent == ["get system status", 'diagnose sniffer packet any "arp" 4 3 l']


@pytest.mark.parametrize("request_, enrolled", [
    ({"recipe": "sniffer", "address": "", "interface": "any", "sniffer_filter": "arp"}, False),
    ({"recipe": "sniffer", "address": CLIENT, "interface": "any", "sniffer_filter": "host"}, False),
    ({"recipe": "sniffer", "address": "", "interface": "any", "sniffer_filter": "arp"}, True),
    ({"recipe": "sniffer", "address": CLIENT, "interface": "any", "sniffer_filter": "host"}, True),
])
def test_finding_1_the_proxy_scopes_the_interface_any_by_enrollment(request_, enrolled) -> None:
    inventory = {"diagnostic_recipes": ("sniffer",), "addresses": (CLIENT,),
                 "interfaces": (INTERFACE, "any") if enrolled else (INTERFACE,)}
    section = SimpleNamespace(egress={}, catalog_platform=lambda: "fortinet", enabled_queries=("system_status",),
                              read_inventory=inventory)
    arguments = proxy.Proxy._validate_tool_arguments("fortios_diagnostics", {"target": "lab-60f", **request_})
    if enrolled:
        proxy.Proxy._authorize_tool("fortios_diagnostics", arguments, None, section)
    else:
        with pytest.raises(proxy.PolicyScopeError):
            proxy.Proxy._authorize_tool("fortios_diagnostics", arguments, None, section)


def test_finding_1_any_can_be_enrolled_beside_fortios_interface_queries_only_for_the_sniffer() -> None:
    from netops_helper.read_policy import validate_query_inventory
    queries = ("system_status", "dhcp_leases")
    validate_query_inventory("fortinet", queries, {"diagnostic_recipes": ("sniffer",), "interfaces": (INTERFACE, "any")})
    with pytest.raises(ValueError, match="enrolled interface is invalid"):
        validate_query_inventory("fortinet", queries, {"diagnostic_recipes": ("logs",), "interfaces": (INTERFACE, "any")})


TUPLE = {"source_address": CLIENT, "source_port": 45123, "destination_port": 53, "protocol": 17}


def test_finding_2_a_policy_with_the_whole_tuple_sets_and_verifies_the_policy_filter(wire, audit_log,
                                                                                      monkeypatch) -> None:
    # Review finding 2: policy_id was accepted with the whole tuple and silently not set.
    session, shell = _shell("sessions_tuple_policy")
    monkeypatch.setattr(engine.core_session, "fortinet_session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    target = _engine_target(diagnostic_recipes=("sessions",), addresses=(CLIENT, PUBLIC))
    result = engine.fortios_diagnostics(target, "sessions", PUBLIC, INTERFACE, 8, 10, 16000, policy_id=5, **TUPLE)
    assert session.sent[4:12] == [
        "diagnose sys session filter src " + CLIENT + " " + CLIENT,
        "diagnose sys session filter dst " + PUBLIC + " " + PUBLIC, "diagnose sys session filter sport 45123 45123",
        "diagnose sys session filter dport 53 53", "diagnose sys session filter proto 17 17",
        "diagnose sys session filter policy 5 5", "diagnose sys session filter", "diagnose sys session list"]
    assert session.sent[-2:] == ["diagnose sys session filter clear", "diagnose sys session filter"]
    assert result["ok"] is True and result["complete"] is True and result["cleanup"] == "verified"
    assert "policy_id=5 " in result["untrusted_device_output"]
    assert "hook=post dir=org act=snat " + CLIENT + ":45123->" + PUBLIC + ":53(" in result["untrusted_device_output"]
    assert result["firmware_support"]["status"] == "tested" and "warnings" not in result


def test_finding_2_a_policy_the_device_does_not_show_with_the_tuple_is_refused_and_cleared() -> None:
    def ignored_policy(responses):
        shown = responses["diagnose sys session filter"]
        shown[1] = shown[1].replace("policy id: 5-5", "policy id: any")

    session, shell = _shell("sessions_tuple_policy", ignored_policy)
    with pytest.raises(ValueError, match="did not show the requested session filter"):
        d.run(shell, "sessions", PUBLIC, INTERFACE, 8, 10, policy_id=5, **TUPLE)
    assert "diagnose sys session list" not in session.sent and "diagnose sys session filter clear" in session.sent


def _logs_engine(monkeypatch, member):
    session, shell = _shell(member)
    fresh = _Replay("fresh")
    shells = iter([shell, engine._FortiosDiagnosticShell(fresh)])
    monkeypatch.setattr(engine.core_session, "fortinet_session", _ClosableSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: next(shells))
    return session, fresh


@pytest.mark.parametrize("until", [None, "2026-11-17 20:09:00"])
def test_zero_found_in_a_partial_search_is_truncated(wire, audit_log, monkeypatch, until):
    _, fresh = _logs_engine(monkeypatch, "logs_deny")
    result = engine.fortios_diagnostics(_engine_target(diagnostic_recipes=("logs",), addresses=(CLIENT,)),
                                        "logs", CLIENT, INTERFACE, until=until, log_category="traffic",
                                        log_action="deny")
    assert result["searched_percent"] == 30.6
    assert (result["found"], result["loaded"], result["matched"], result["returned"]) == (0, 0, 0, 0)
    assert not result["ok"] and result["log_state"] == "incomplete" and result["truncated"]
    assert result["cleanup"] == "verified" and fresh.sent == []


def test_finding_3_a_window_that_empties_a_partial_search_is_incomplete(wire, audit_log, monkeypatch) -> None:
    # Review finding 3: five records newer than `until`, 4.0 % searched: not an empty success.
    session, fresh = _logs_engine(monkeypatch, "logs_system")
    result = engine.fortios_diagnostics(_engine_target(diagnostic_recipes=("logs",)), "logs", "", INTERFACE, 3, 10,
                                        16000, until="2026-11-17 20:09:00", log_category="event",
                                        log_subtype="system")
    assert result["searched_percent"] == 4.0 and (result["found"], result["loaded"], result["matched"]) == (130, 5, 0)
    assert result["ok"] is False and result["log_state"] == "incomplete" and result["truncated"] is True
    assert result["cleanup"] == "verified" and fresh.sent == []


def test_finding_3_a_window_inside_a_partial_search_still_answers_its_records(wire, audit_log, monkeypatch) -> None:
    session, fresh = _logs_engine(monkeypatch, "logs_system")
    result = engine.fortios_diagnostics(_engine_target(diagnostic_recipes=("logs",)), "logs", "", INTERFACE, 3, 10,
                                        16000, since="2026-11-17 20:09:20", log_category="event",
                                        log_subtype="system")
    assert result["ok"] is True and result["log_state"] == "ok" and result["matched"] == 3


def test_finding_4_event_logs_of_the_sdwan_subtype(wire, audit_log, monkeypatch) -> None:
    # Review finding 4 (FP-01): the sdwan subtype; measured on the lab 60F (no SD-WAN events: 0 found,
    # the whole log searched).
    session, fresh = _logs_engine(monkeypatch, "logs_sdwan")
    result = engine.fortios_diagnostics(_engine_target(diagnostic_recipes=("logs",)), "logs", "", INTERFACE, 3, 10,
                                        16000, log_category="event", log_subtype="sdwan")
    assert session.sent[4:9] == ["execute log filter category event", "execute log filter field subtype sdwan",
                                 "execute log filter view-lines 5", "execute log filter dump", "execute log display"]
    assert result["filter_applied"]["Filter"] == '( subtype "sdwan" )'
    assert result["ok"] is True and result["log_state"] == "empty" and result["found"] == 0
    assert result["searched_percent"] is None and result["cleanup"] == "verified"


def test_finding_4_traffic_logs_of_one_policy_are_filtered_on_the_device(wire, audit_log, monkeypatch) -> None:
    # Review finding 4 (FP-01): `execute log filter field policyid <n>` before the display (measured).
    session, fresh = _logs_engine(monkeypatch, "logs_policy")
    result = engine.fortios_diagnostics(_engine_target(diagnostic_recipes=("logs",)), "logs", "", INTERFACE, 3, 10,
                                        16000, log_category="traffic", policy_id=5)
    assert session.sent[4:9] == ["execute log filter category traffic", "execute log filter field policyid 5",
                                 "execute log filter view-lines 5", "execute log filter dump", "execute log display"]
    assert result["filter_applied"]["Filter"] == '( policyid "5" )'
    assert result["ok"] is True and result["log_state"] == "ok" and result["searched_percent"] == 16.2
    assert result["returned"] == 3 and result["untrusted_device_output"].count(" policyid=5 ") == 3
    assert result["firmware_support"]["status"] == "tested" and result["cleanup"] == "verified"


@pytest.mark.parametrize("extra, accepted", [
    ({"recipe": "logs", "address": "", "log_category": "event", "log_subtype": "sdwan"}, True),
    ({"recipe": "logs", "address": "", "log_category": "traffic", "policy_id": 5}, True),
    ({"recipe": "logs", "address": CLIENT, "log_category": "traffic", "log_action": "deny", "policy_id": 7}, True),
    ({"recipe": "logs", "address": "", "log_category": "event", "policy_id": 5}, False),
    ({"recipe": "logs", "address": "", "policy_id": 5}, False),
    ({"recipe": "logs", "address": "", "log_category": "traffic", "policy_id": 0}, False),
    ({"recipe": "logs", "address": "", "log_category": "traffic", "log_subtype": "sdwan"}, False),
])
def test_finding_4_the_proxy_and_the_recipe_take_sdwan_and_a_log_policy(extra, accepted) -> None:
    g10 = {name: extra.get(name) for name in ("log_category", "log_subtype", "log_action", "policy_id")}
    if accepted:
        assert _proxy_call(**extra)["recipe"] == "logs"
        d.validate("logs", extra["address"], INTERFACE, 3, 10, 16000, **g10)
    else:
        with pytest.raises(proxy.ToolArgumentsError):
            _proxy_call(**extra)
        with pytest.raises(ValueError):
            d.validate("logs", extra["address"], INTERFACE, 3, 10, 16000, **g10)
