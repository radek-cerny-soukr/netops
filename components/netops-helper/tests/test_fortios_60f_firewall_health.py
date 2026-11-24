"""FIREWALL-HEALTH (1.0.12): ping and traceroute to IPv6 and DNS name targets, from an explicit source, and the plain
recipes measured on the lab FortiGate-60F 7.6.8 build 3744 (FP-03, FP-04, FOS-P05).

The fixture holds the bytes a read-only account received from the lab 60F for exactly the commands these recipes
send (verification, anonymised; see its "source"). The fake session answers each sent command with the recorded bytes,
so the real diagnostic shell, the real recipe and the real restore checks run unchanged.
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
from netops_helper.read_policy import validate_query_inventory
from test_error_branches_helper_engine import _OpenSession, _assert_audit, _diagnostic_target, audit_log  # noqa: F401

# Integration 461: the fixture is not named fortios_*.json, so it stays out of the historical classifier captures
# (support/classification_fixtures.real_captures, output_status_baseline.json).
RECORDED = json.loads(pathlib.Path(__file__).with_name("fixtures").joinpath("firewall_health_fortios_60f_768.json").read_text())
INTERFACE = "wan1"
WAN_ADDRESS = "192.0.2.100"           # the wan1 address of the 60F (diagnose ip address list)
PUBLIC = "203.0.113.244"              # what one.one.one.one resolved to
PUBLIC_OTHER = "203.0.113.245"
NAME = "one.one.one.one"
LINK_LOCAL = "fe80::10"               # the wan1 link-local address of the 60F itself
UNROUTED = "2001:db8:1::8888"         # the 60F has no IPv6 route
SIXTY_F = ("FortiGate-60F", "7.6.8", "3744")


class _Replay:
    """One recorded session: every command answers its recorded bytes; several answers are given in order."""

    def __init__(self, member: str) -> None:
        recorded = RECORDED["members"][member]
        self.responses = {command: [answer] + recorded.get("repeats", {}).get(command, [])
                          for command, answer in recorded["responses"].items()}
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


def _shell(member: str = "probe"):
    session = _Replay(member)
    return session, engine._FortiosDiagnosticShell(session)


def _option_commands(session, prefix):
    return [command for command in session.sent if command.startswith(prefix) and not command.endswith("view-settings")]


def _restored(session, prefix):
    """Every option the recipe set was set back to the value read before, and the state was read again."""
    commands = _option_commands(session, prefix)
    half = len(commands) // 2
    assert half and [c.rsplit(" ", 1)[0] for c in commands[:half]] == [c.rsplit(" ", 1)[0] for c in commands[half:]][::-1]
    assert session.sent[-1] == prefix + "view-settings" and session.sent.count(prefix + "view-settings") == 2
    return commands[:half], commands[half:]


# --- FP-03: the plain recipes on the 60F are tested now -------------------------------------------------------

def test_plain_ping_on_the_60f_is_tested_and_restores_its_options() -> None:
    session, shell = _shell()
    support = []
    output, timed_out, identity, domain = d.run(shell, "ping", PUBLIC, INTERFACE, 2, 10, support=support)
    assert "2 packets transmitted, 1 packets received, 50% packet loss" in output
    assert not timed_out and identity == SIXTY_F and domain == "root"
    assert "execute ping " + PUBLIC in session.sent and "diagnose ip address list" not in session.sent
    set_, restore = _restored(session, "execute ping-options ")
    assert "execute ping-options source auto" in set_ and "execute ping-options repeat-count 5" in restore
    assert support[0]["status"] == "tested" and support[0]["message"] is None


def test_logs_on_the_60f_verify_the_session_scoped_filter_through_a_new_session() -> None:
    # Measured: `execute log display` advances start-line and adds an empty Filter line in this session only;
    # a new session reads the filter as before, so the recipe's reconnect verifies it.
    session, shell = _shell("logs")
    fresh = _Replay("fresh")

    @contextmanager
    def reconnect():
        yield engine._FortiosDiagnosticShell(fresh)

    support = []
    result, timed_out, identity, domain = d.run(shell, "logs", "203.0.113.238", INTERFACE, 3, 10, reconnect=reconnect,
                                                support=support)
    assert result["state"] == "ok" and (result["found"], result["loaded"]) == (441, 10)
    assert result["matched"] == 10 and result["returned"] == 3 and result["truncated"] is True
    assert result["output"].count("srcip=203.0.113.238 ") == 3
    assert session.sent.count("execute log filter dump") == 2 and fresh.sent == ["get system status", "execute log filter dump"]
    assert support[0]["status"] == "tested"


def test_logs_on_the_60f_without_a_new_session_stay_unverified() -> None:
    session, shell = _shell("logs")
    with pytest.raises(d.RestoreUnverified):
        d.run(shell, "logs", "203.0.113.238", INTERFACE, 3, 10)


def test_sessions_without_a_tuple_on_the_60f_are_tested_and_clear_the_filter() -> None:
    session, shell = _shell("logs")
    support = []
    output, timed_out, identity, domain = d.run(shell, "sessions", PUBLIC_OTHER, INTERFACE, 8, 10, support=support)
    assert "total session: 2" in output and output.count("session info: proto=1 ") == 2
    assert session.sent[-2:] == ["diagnose sys session filter clear", "diagnose sys session filter"]
    assert support[0]["status"] == "tested"


# --- FOS-P05: an explicit source address -----------------------------------------------------------------------

def test_ping_from_the_wan_address_sets_and_restores_the_source() -> None:
    session, shell = _shell()
    support = []
    output, timed_out, _, _ = d.run(shell, "ping", PUBLIC_OTHER, INTERFACE, 2, 10, source_address=WAN_ADDRESS,
                                    support=support)
    assert "2 packets transmitted, 1 packets received" in output
    assert session.sent.index("diagnose ip address list") < session.sent.index("execute ping-options view-settings")
    set_, restore = _restored(session, "execute ping-options ")
    assert "execute ping-options source " + WAN_ADDRESS in set_ and "execute ping-options source auto" in restore
    assert support[0]["status"] == "tested" and support[0]["message"] is None


def test_traceroute_from_the_wan_address_reports_the_source_the_device_used() -> None:
    session, shell = _shell()
    support = []
    output, _, _, _ = d.run(shell, "traceroute", PUBLIC_OTHER, INTERFACE, 1, 10, source_address=WAN_ADDRESS,
                            support=support)
    assert output.startswith("traceroute to " + PUBLIC_OTHER) and "from ip address " + WAN_ADDRESS in output
    set_, restore = _restored(session, "execute traceroute-options ")
    assert "execute traceroute-options source " + WAN_ADDRESS in set_
    assert "execute traceroute-options source auto" in restore
    assert support[0]["status"] == "tested"


def test_a_source_that_is_not_an_address_of_the_fortigate_is_refused_before_any_option() -> None:
    # Measured: a foreign source is accepted by ping-options and the ping then only shows 100% packet loss.
    session, shell = _shell()
    with pytest.raises(ValueError, match=r"^the source address is not an address of this FortiGate"):
        d.run(shell, "ping", PUBLIC_OTHER, INTERFACE, 2, 10, source_address="192.0.2.99")
    assert session.sent[-1] == "diagnose ip address list"
    assert not any("-options" in command for command in session.sent)


# --- FP-04: DNS name and IPv6 targets ------------------------------------------------------------------------------

def test_ping_and_traceroute_to_a_dns_name_resolve_on_the_device() -> None:
    session, shell = _shell()
    support = []
    output, _, _, _ = d.run(shell, "ping", NAME, INTERFACE, 2, 10, support=support)
    assert output.startswith("PING " + NAME + " (" + PUBLIC + "): 56 data bytes")
    _restored(session, "execute ping-options ")
    assert support[0]["status"] == "tested"
    session, shell = _shell()
    output, _, _, _ = d.run(shell, "traceroute", NAME, INTERFACE, 1, 10, support=support)
    assert output.startswith("traceroute to " + NAME + " (" + PUBLIC + ")") and output.rstrip().endswith("<" + NAME + ">  7.540 ms")
    _restored(session, "execute traceroute-options ")
    assert support[0]["status"] == "tested"


def test_ping6_binds_the_interface_and_restores_the_ipv6_options() -> None:
    session, shell = _shell()
    support = []
    output, _, _, _ = d.run(shell, "ping", LINK_LOCAL, INTERFACE, 2, 10, support=support)
    assert "2 packets transmitted, 2 packets received, 0% packet loss" in output
    assert "execute ping6 -I wan1 " + LINK_LOCAL in session.sent
    set_, restore = _restored(session, "execute ping6-options ")
    assert "execute ping6-options source6 auto" in set_ and "execute ping6-options interface auto" in restore
    assert not any(command.startswith("execute ping-options") for command in session.sent)
    assert support[0]["status"] == "tested"


def test_ping6_without_a_route_returns_the_device_answer() -> None:
    session, shell = _shell()
    output, _, _, _ = d.run(shell, "ping", UNROUTED, INTERFACE, 2, 10)
    assert output == "connect: Network is unreachable"
    _restored(session, "execute ping6-options ")


@pytest.mark.parametrize("address,first,last", [
    (LINK_LOCAL, "tracert6 to fe80::10", "1  fe80::10                 (fe80::10)  0.157 ms"),
    (UNROUTED, "tracert6 to " + UNROUTED, "30  *"),
])
def test_ipv6_traceroute_is_tracert6_with_its_own_arguments(address, first, last) -> None:
    session, shell = _shell()
    support = []
    output, _, _, _ = d.run(shell, "traceroute", address, INTERFACE, 1, 10, support=support)
    assert output.startswith(first) and output.rstrip().endswith(last)
    assert session.sent[-1] == "execute tracert6 -q 1 -i wan1 " + address
    assert not any("-options" in command for command in session.sent)
    assert support[0]["status"] == "tested"


@pytest.mark.parametrize("address,kwargs,part", [
    (LINK_LOCAL, {}, "with an IPv6 target"),
    (NAME, {}, "with a DNS name target"),
    (PUBLIC_OTHER, {"source_address": WAN_ADDRESS}, "with an explicit source address"),
])
def test_another_identity_runs_the_new_parts_with_an_untested_warning(address, kwargs, part) -> None:
    session, shell = _shell()
    status = session.responses["get system status"]
    status[0] = status[0].replace("v7.6.8,build3744", "v7.6.9,build3800")
    support = []
    d.run(shell, "ping", address, INTERFACE, 2, 10, support=support, **kwargs)
    assert support[0]["status"] == "untested" and support[0]["device_version"] == "7.6.9 build3800"
    assert ("fortios_diagnostics ping " + part) in support[0]["message"]


# --- validation and enrollment ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("recipe,address,source", [
    ("ping", LINK_LOCAL, None), ("ping", UNROUTED, None), ("traceroute", UNROUTED, None), ("ping", NAME, None),
    ("traceroute", NAME, WAN_ADDRESS), ("ping", PUBLIC, WAN_ADDRESS),
])
def test_valid_probe_targets_and_sources(recipe, address, source) -> None:
    d.validate(recipe, address, INTERFACE, 2 if recipe == "ping" else 1, 10, 16000, source_address=source)


@pytest.mark.parametrize("recipe,address,kwargs", [
    ("ping", "ff02::1", {}), ("ping", "::", {}), ("ping", "FE80::10", {}), ("ping", "fe80::0010", {}),
    ("ping", "One.one.one.one", {}), ("ping", "localhost", {}), ("ping", "one.one.one.one;reboot", {}),
    ("sessions", LINK_LOCAL, {}), ("sessions", NAME, {}), ("sniffer", NAME, {}),
    ("ping", UNROUTED, {"source_address": WAN_ADDRESS}), ("ping", PUBLIC, {"source_address": LINK_LOCAL}),
    ("ping", PUBLIC, {"source_address": "192.0.2.0/24"}), ("ping", PUBLIC, {"source_address": NAME}),
    ("ping", PUBLIC, {"source_address": WAN_ADDRESS, "destination_port": 443}),
])
def test_invalid_probe_requests(recipe, address, kwargs) -> None:
    with pytest.raises(ValueError):
        d.validate(recipe, address, INTERFACE, 2, 10, 16000, **kwargs)


class _Auth:
    fortios_output_standard_verified = True

    def __init__(self, **inventory):
        self.read_inventory = {"diagnostic_recipes": ("ping", "traceroute"), "interfaces": (INTERFACE,), **inventory}

    def require_ssh_query(self, platform, query):
        assert (platform, query) == ("fortinet", "system_status")


def test_a_dns_name_needs_diagnostic_names_and_an_ipv6_address_needs_addresses() -> None:
    d.authorize(_Auth(diagnostic_names=(NAME,)), "ping", NAME, INTERFACE)
    d.authorize(_Auth(addresses=(LINK_LOCAL,)), "traceroute", LINK_LOCAL, INTERFACE)
    d.authorize(_Auth(addresses=(PUBLIC, WAN_ADDRESS)), "ping", PUBLIC, INTERFACE, source_address=WAN_ADDRESS)
    for auth, address, source in ((_Auth(addresses=(NAME,)), NAME, None), (_Auth(diagnostic_names=()), NAME, None),
                                  (_Auth(addresses=(UNROUTED,)), LINK_LOCAL, None),
                                  (_Auth(addresses=(PUBLIC,)), PUBLIC, WAN_ADDRESS)):
        with pytest.raises(ValueError, match="^diagnostic scope is not enrolled for this target$"):
            d.authorize(auth, "ping", address, INTERFACE, source_address=source)


def test_fortios_inventory_may_enroll_dns_names_now() -> None:
    validate_query_inventory("fortios", (), {"diagnostic_recipes": ("ping",), "diagnostic_names": (NAME,)})
    with pytest.raises(ValueError, match="enrolled diagnostic DNS names exist only on"):
        validate_query_inventory("cisco_ios", (), {"diagnostic_names": (NAME,)})


def _proxy_call(**extra):
    return proxy.Proxy._validate_tool_arguments("fortios_diagnostics", {"target": "lab-60f", "interface": INTERFACE,
                                                                        "recipe": "ping", **extra})


@pytest.mark.parametrize("extra", [
    {"address": LINK_LOCAL}, {"address": NAME}, {"recipe": "traceroute", "address": UNROUTED, "count": 1},
    {"address": PUBLIC, "source_address": WAN_ADDRESS}, {"address": NAME, "source_address": WAN_ADDRESS},
])
def test_proxy_accepts_the_new_probe_arguments(extra) -> None:
    assert _proxy_call(**extra)["address"] == extra["address"]


@pytest.mark.parametrize("extra", [
    {"address": "ff02::1"}, {"address": "One.One.One.One"}, {"recipe": "sessions", "address": LINK_LOCAL},
    {"address": UNROUTED, "source_address": WAN_ADDRESS}, {"address": PUBLIC, "source_address": LINK_LOCAL},
    {"address": PUBLIC, "source_address": "192.0.2.0/24"}, {"address": "", "interface": "", "recipe": "ping"},
    {"address": NAME, "interface": ""},
])
def test_proxy_refuses_other_probe_arguments(extra) -> None:
    with pytest.raises(proxy.ToolArgumentsError):
        _proxy_call(**extra)


def test_proxy_scope_needs_the_enrolled_dns_name() -> None:
    inventory = {"diagnostic_recipes": ("ping",), "interfaces": (INTERFACE,), "diagnostic_names": (NAME,),
                 "addresses": (WAN_ADDRESS,)}
    section = SimpleNamespace(egress={}, catalog_platform=lambda: "fortinet", enabled_queries=("system_status",),
                              read_inventory=inventory)
    request = {"target": "lab-60f", "recipe": "ping", "address": NAME, "interface": INTERFACE,
               "source_address": WAN_ADDRESS}
    proxy.Proxy._authorize_tool("fortios_diagnostics", request, None, section)
    for category in ("diagnostic_names", "addresses"):
        section.read_inventory = {**inventory, category: ()}
        with pytest.raises(proxy.PolicyScopeError):
            proxy.Proxy._authorize_tool("fortios_diagnostics", request, None, section)


# --- the engine answer ---------------------------------------------------------------------------------------------

def _engine_target(**inventory):
    target = _diagnostic_target()
    return replace(target, read_inventory={**target.read_inventory, "diagnostic_recipes": ("ping", "traceroute"),
                                           "interfaces": (INTERFACE,), **inventory})


def test_the_engine_answers_a_dns_name_ping_on_the_60f_as_tested(wire, audit_log, monkeypatch) -> None:
    session, shell = _shell()
    monkeypatch.setattr(engine.core_session, "fortinet_session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    result = engine.fortios_diagnostics(_engine_target(diagnostic_names=(NAME,)), "ping", NAME, INTERFACE, 2, 10,
                                        16000)
    assert result["ok"] is True and result["cleanup"] == "verified" and result["identity"] == SIXTY_F
    assert result["untrusted_device_output"].startswith("PING " + NAME + " (" + PUBLIC + ")")
    assert result["firmware_support"]["status"] == "tested" and "warnings" not in result
    events = _assert_audit(audit_log, "fortios_diagnostics", ["started", "ok"])
    assert [event.get("destination_address") for event in events] == [NAME, NAME]


def test_the_engine_audits_an_ipv6_probe_target(wire, audit_log, monkeypatch) -> None:
    session, shell = _shell()
    monkeypatch.setattr(engine.core_session, "fortinet_session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    result = engine.fortios_diagnostics(_engine_target(addresses=(LINK_LOCAL,)), "traceroute", LINK_LOCAL,
                                        INTERFACE, 1, 10, 16000)
    assert result["ok"] and result["untrusted_device_output"].startswith("tracert6 to " + LINK_LOCAL)
    events = _assert_audit(audit_log, "fortios_diagnostics", ["started", "ok"])
    assert [event.get("destination_address") for event in events] == [LINK_LOCAL, LINK_LOCAL]


def test_the_engine_does_not_audit_an_unenrolled_probe_name(wire, audit_log, monkeypatch) -> None:
    session, shell = _shell()
    monkeypatch.setattr(engine.core_session, "fortinet_session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    with pytest.raises(ValueError, match="not enrolled"):
        engine.fortios_diagnostics(_engine_target(), "ping", NAME, INTERFACE, 2, 10)
    assert not session.sent
    events = _assert_audit(audit_log, "fortios_diagnostics", ["started", "failed"])
    assert all("destination_address" not in event for event in events)


def test_the_engine_names_a_foreign_source_as_the_reason(wire, audit_log, monkeypatch) -> None:
    session, shell = _shell()
    monkeypatch.setattr(engine.core_session, "fortinet_session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    result = engine.fortios_diagnostics(_engine_target(addresses=(PUBLIC_OTHER, "192.0.2.99")), "ping", PUBLIC_OTHER,
                                        INTERFACE, 2, 10, 16000, source_address="192.0.2.99")
    assert result["ok"] is False and result["error_code"] == "source_not_local"
    assert "source address is not an address of this FortiGate" in result["error"]
    assert "192.0.2.99" not in json.dumps(result)
    _assert_audit(audit_log, "fortios_diagnostics", ["started", "failed"])
    assert not any("-options" in command for command in session.sent)


# --- FP-03: the client answer of sessions without a tuple keeps the addresses of local ICMP sessions --------

SESSIONS_PROJECTED_60F = (
    "session proto=1 proto_state=00 duration=40 expire=20 policy_id=0 dev=18->5/5->18 org=168/2/1 reply=168/2/1\n"
    "hook=out dir=org act=noop " + WAN_ADDRESS + ":5->" + PUBLIC_OTHER + ":8(0.0.0.0:0)\n"
    "hook=in dir=reply act=noop " + PUBLIC_OTHER + ":5->" + WAN_ADDRESS + ":0(0.0.0.0:0)\n"
    "session proto=1 proto_state=00 duration=31 expire=33 policy_id=0 dev=18->5/5->18 org=252/3/1 reply=0/0/0\n"
    "hook=out dir=org act=noop " + WAN_ADDRESS + ":43297->" + PUBLIC_OTHER + ":8(0.0.0.0:0)\n"
    "hook=in dir=reply act=noop " + PUBLIC_OTHER + ":43297->" + WAN_ADDRESS + ":0(0.0.0.0:0)\n"
    "total session: 2\n")


def test_the_engine_answers_60f_sessions_without_a_tuple_with_both_directions(wire, audit_log, monkeypatch) -> None:
    # Measured on the 60F 7.6.8: a ping sent by the FortiGate itself is a local session with hook=out dir=org and
    # hook=in dir=reply (not pre/post); the client must get both directions with their addresses and complete=true.
    session, shell = _shell("logs")
    monkeypatch.setattr(engine.core_session, "fortinet_session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    result = engine.fortios_diagnostics(_engine_target(diagnostic_recipes=("sessions",), addresses=(PUBLIC_OTHER,)),
                                        "sessions", PUBLIC_OTHER, INTERFACE, 8, 10, 16000)
    assert result["untrusted_device_output"] == SESSIONS_PROJECTED_60F
    assert "incomplete=" not in result["untrusted_device_output"]
    assert result["complete"] is True and result["sessions_omitted"] == 0 and result["truncated"] is False
    assert result["ok"] is True and result["cleanup"] == "verified" and result["identity"] == SIXTY_F
    assert result["firmware_support"]["status"] == "tested" and "warnings" not in result
    assert session.sent[-2:] == ["diagnose sys session filter clear", "diagnose sys session filter"]
    _assert_audit(audit_log, "fortios_diagnostics", ["started", "ok"])


@pytest.mark.parametrize("hook", ["hook=fwd dir=org", "hook=out dir=xyz", "hook=output dir=org"])
def test_an_unknown_hook_shape_of_the_60f_session_stays_incomplete(hook) -> None:
    raw = RECORDED["members"]["logs"]["responses"]["diagnose sys session list"].replace("\r", "")
    changed = raw.replace("hook=out dir=org", hook)
    assert changed != raw
    text, complete, omitted = d.session_projection(changed, 8)
    assert complete is False and omitted == 0 and text.count("incomplete=hook\n") == 2
    assert "hook=in dir=reply act=noop " + PUBLIC_OTHER + ":5->" + WAN_ADDRESS + ":0(0.0.0.0:0)\n" in text
