"""triage_flow with a known or unknown source port (verification-05).

The end to end cases drive the real Proxy.request -> TargetAuth.decode -> engine.triage_flow -> triage_flow chain; only
the SSH transport is replaced (`engine.read_from_device` and the diagnostic shell). The device outputs are the existing
anonymised FortiGate-80F 8.0.2 captures of the tests (a derived replay, not a new live measurement); the only derived
text is a session list whose second session carries another policy id, built by editing one capture line below.
"""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import netops_core.target_lock
from netops_core.audit import Recorder

import netops_helper.audit as audit
import netops_helper.engine as engine
from netops_helper import fortios_diagnostics as diagnostics
from netops_helper import proxy as proxy_module
from netops_helper import triage_flow as t
from netops_helper.auth import TargetAuth
import test_proxy_contracts as c
import test_triage_flow as base
from test_triage_flow import audit_log  # noqa: F401  (fixture)

SRC = "192.0.2.11"
DST = "203.0.113.53"
UDP = {"src": SRC, "dst": DST, "port": 53, "proto": "udp"}
QUERIES = ("system_status", "route_lookup", "policy_lookup_ipv4")
NO_ROUTE = "Routing table for VRF=default(0)\n% Network not in table\n"
SEEN = base.live("session_seen")  # two sessions of this tuple: source ports 40640 and 40641, both policy 3
SEEN_TWO_POLICIES = SEEN.replace("misc=0 policy_id=3 pol_uuid_idx=26053 auth_info=0 chk_client_info=0 vd=0\nserial=00001a02",
                                 "misc=0 policy_id=7 pol_uuid_idx=26053 auth_info=0 chk_client_info=0 vd=0\nserial=00001a02")
ONE_SESSION = SEEN.split("\nsession info:")[0] + "\ntotal session: 1\n"
LOOKUP = "diagnose firewall iprope lookup " + SRC + " %s " + DST + " 53 17 LAN-test policy"


def _lookup_commands(sent):
    return [command for command in sent if command.startswith("diagnose firewall iprope lookup")]


class Shell(base.FakeShell):
    created = []

    def __init__(self):
        super().__init__()
        Shell.created.append(self)


@pytest.fixture()
def wire(tmp_path, monkeypatch):
    """The real proxy with one enrolled FortiGate and a fake SSH transport; returns call(arguments, ...)."""
    inventory, _, _, _ = c._configure(proxy_module, tmp_path)
    section = c._section()
    section.update(ssh_platform="fortios", device_types=["firewall"], enabled_queries=list(QUERIES))
    section["read_inventory"].update(interfaces=["LAN-test"], diagnostic_recipes=["sessions"])
    c._write(inventory, c._inventory(c._device(section, "fortios")))
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    sent = []
    state = {"route_dst": base.live("route_dst_internet"), "session": SEEN, "lookup": base.live("policy_accept")}

    def device(auth, platform, command, **_):
        sent.append(command)
        if command == "get system status":
            return 0, base.live("status")
        if command == "get router info routing-table details " + DST:
            return 0, state["route_dst"]
        if command == "get router info routing-table details " + SRC:
            return 0, base.live("route_src_lan")
        if command.startswith("diagnose firewall iprope lookup"):
            return 0, state["lookup"]
        pytest.fail("unexpected device command " + command)

    Shell.created = []
    monkeypatch.setattr(engine, "read_from_device", device)
    monkeypatch.setattr(diagnostics, "_bounded", lambda shell, command, timeout, grace=3: (state["session"], False))
    monkeypatch.setattr(netops_core.target_lock, "target_lock", lambda fingerprint: nullcontext())
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: ["192.0.2.10"])
    monkeypatch.setattr(engine, "host_key_line", lambda *a: "pinned")
    monkeypatch.setattr(engine, "_paced_connection", lambda *a: nullcontext())
    monkeypatch.setattr(engine, "DeviceCredential", lambda auth: None)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda session: Shell())
    monkeypatch.setattr(engine.core_session, "fortinet_session",
                        lambda *a, **k: nullcontext(SimpleNamespace(close=lambda: None)))

    def call(arguments, **changes):
        state.update(changes)
        forwarded = proxy_module.Proxy().request(c._request(1, "triage_flow", {"target": "device-a", **arguments}))
        assert forwarded is not None, "the proxy refused the call"
        args = json.loads(forwarded)["params"]["arguments"]
        auth = TargetAuth.decode(args.pop("target"), args.pop("auth_context"))
        return engine.triage_flow(auth, **args)

    call.sent = sent
    call.state = state
    return call


def _filters():
    return [command for shell in Shell.created for command in shell.commands
            if command.startswith("diagnose sys session filter ") and "clear" not in command]


# ---- unknown source port: nothing is invented ----------------------------------------------------------------------
def test_omitted_source_port_through_the_proxy_runs_no_lookup_and_reads_the_sessions_of_any_source_port(wire):
    result = wire(UDP)
    assert wire.sent[:3] == ["get system status", "get router info routing-table details " + DST,
                             "get router info routing-table details " + SRC]
    assert _lookup_commands(wire.sent) == [], "an unknown source port must not reach the iprope lookup"
    assert result["verdict"] == "incomplete" and result["ok"] is True
    assert {"step": "policy_lookup", "reason": "source_port_unknown"} in result["missing"]
    assert result["chain"]["policy"] is None and "policy_lookup" not in result["checked"]
    assert result["chain"]["ingress"]["interface"] == "LAN-test" and result["chain"]["egress"]["interfaces"]
    assert result["flow"] == {**UDP, "source_port": None}
    assert result["vantage"]["policy_lookup_source_port"] is None
    assert not any(f["id"].startswith("F-FLOW-POLICY") for f in result["findings"])
    assert "40000" not in json.dumps(result)
    assert _filters() == ["diagnose sys session filter src " + SRC, "diagnose sys session filter dst " + DST,
                          "diagnose sys session filter dport 53", "diagnose sys session filter proto 17"]
    session = result["chain"]["session"]
    assert session["state"] == "read" and session["matching"] == 2
    assert [item["source_port"] for item in session["sessions"]] == [40640, 40641]
    assert session["exhaustive_for_any_source_port"] is False
    assert "not a policy lookup" in session["note"]


def test_explicit_none_is_the_same_unknown_port(wire):
    result = wire({**UDP, "source_port": None})
    assert _lookup_commands(wire.sent) == [] and result["flow"]["source_port"] is None
    assert {"step": "policy_lookup", "reason": "source_port_unknown"} in result["missing"]


def test_several_observed_source_ports_and_policy_ids_are_not_merged_into_one_policy(wire):
    result = wire(UDP, session=SEEN_TWO_POLICIES)
    session = result["chain"]["session"]
    assert [(s["source_port"], s["policy_id"]) for s in session["sessions"]] == [(40640, 3), (40641, 7)]
    assert session["observed_policy_ids"] == [3, 7]
    assert result["chain"]["policy"] is None and result["verdict"] == "incomplete"
    assert [f for f in result["findings"] if f["id"] == "F-FLOW-SESSION"][0]["fact"].startswith("2 sessions")
    assert "any source port" in [f for f in result["findings"] if f["id"] == "F-FLOW-SESSION"][0]["fact"]


def test_unknown_port_with_an_empty_session_list_is_still_incomplete(wire):
    result = wire(UDP, session=base.live("session_none"))
    assert result["chain"]["session"]["matching"] == 0 and result["verdict"] == "incomplete"
    assert {"step": "policy_lookup", "reason": "source_port_unknown"} in result["missing"]


def test_unknown_port_keeps_the_session_report_limit_visible(wire):
    block = SEEN.split("\nsession info:")[0]
    many = "".join(block.replace(":40640", ":%d" % (41000 + n)).replace(":40641", ":%d" % (41000 + n)) + "\n"
                   for n in range(7)) + "total session: 7\n"
    result = wire(UDP, session=many)
    session = result["chain"]["session"]
    assert session["matching"] == 7 and len(session["sessions"]) == t.SESSION_REPORTED
    assert session["reported"] == t.SESSION_REPORTED and session["truncated"] is True


def test_unknown_port_without_the_session_recipe_says_not_enrolled(wire, monkeypatch):
    result = wire(UDP)
    assert result["chain"]["session"]["state"] == "read"
    def no_recipe(auth, flow, interface):
        return {"ok": False, "reason": "not_enrolled"}
    monkeypatch.setattr(engine, "_flow_session_text", no_recipe)
    result = wire(UDP)
    assert {"step": "session", "reason": "not_enrolled"} in result["missing"]
    assert {"step": "policy_lookup", "reason": "source_port_unknown"} in result["missing"]
    assert result["verdict"] == "incomplete"


def test_proven_no_route_is_not_hidden_by_the_unknown_source_port(wire):
    result = wire(UDP, route_dst=NO_ROUTE)
    assert result["verdict"] == "no_route" and result["missing"] == []
    assert _lookup_commands(wire.sent) == [] and result["chain"]["session"] == {"state": "not_run"}


def test_other_missing_steps_stay_visible_beside_the_unknown_source_port(wire, monkeypatch):
    # no ingress route: the lookup could not have run anyway, so only its own reason is reported
    def device(auth, platform, command, **_):
        if command == "get router info routing-table details " + SRC:
            return 0, NO_ROUTE
        return 0, base.live("route_dst_internet") if "details" in command else base.live("status")
    monkeypatch.setattr(engine, "read_from_device", device)
    result = wire(UDP)
    assert {"step": "policy_lookup", "reason": "ingress_unknown"} in result["missing"]
    assert {"step": "policy_lookup", "reason": "source_port_unknown"} not in result["missing"]
    assert result["chain"]["session"] == {"state": "not_run"}


@pytest.mark.parametrize("exception,reason", [(diagnostics.RestoreUnverified, "restore_unverified"),
                                              (diagnostics.ScopeRefused, "scope_refused")])
def test_restore_and_scope_failures_of_the_session_read_stay_visible_for_an_unknown_port(wire, monkeypatch,
                                                                                         exception, reason):
    def fail(*a, **k):
        raise exception("untrusted exception text")
    monkeypatch.setattr(diagnostics, "run", fail)
    result = wire(UDP)
    assert result["ok"] is False and result["error_code"] == reason and result["failed_step"] == "session"
    assert {"step": "session", "reason": reason} in result["missing"]
    assert {"step": "policy_lookup", "reason": "source_port_unknown"} in result["missing"]
    assert _lookup_commands(wire.sent) == [] and "untrusted exception text" not in json.dumps(result)


def test_icmp_stays_unsupported_for_the_lookup(wire):
    result = wire({"src": SRC, "dst": DST, "port": 1, "proto": "icmp"})
    assert {"step": "policy_lookup", "reason": "unsupported"} in result["missing"]
    assert {"step": "policy_lookup", "reason": "source_port_unknown"} not in result["missing"]
    assert _lookup_commands(wire.sent) == [] and result["vantage"]["policy_lookup_source_port"] is None


# ---- known source port ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("port", [1, 40000, 40640, 65535])
def test_known_source_port_is_the_one_the_policy_lookup_and_the_report_use(wire, port):
    result = wire({**UDP, "source_port": port}, session=ONE_SESSION.replace("40640", str(port)).replace("40641", str(port)))
    assert _lookup_commands(wire.sent) == [LOOKUP % port]
    assert result["flow"] == {**UDP, "source_port": port}
    assert result["vantage"]["policy_lookup_source_port"] == port
    fact = [f for f in result["findings"] if f["id"] == "F-FLOW-POLICY-ACCEPT"][0]["fact"]
    assert "source port %d " % port in fact
    assert any(str(port) in item for item in result["assumptions"])
    if port != 40000:
        assert "40000" not in json.dumps(result) and "40000" not in " ".join(wire.sent)
    assert "diagnose sys session filter sport " + str(port) in _filters()
    assert result["chain"]["policy"]["policy_id"] == 3 and "source_port_unknown" not in json.dumps(result["missing"])


def test_known_source_port_session_matches_only_that_port(wire):
    result = wire({**UDP, "source_port": 40640}, session=ONE_SESSION)
    session = result["chain"]["session"]
    assert result["verdict"] == "allowed_and_session_seen" and result["missing"] == []
    assert session["matching"] == 1 and session["sessions"][0]["source_port"] == 40640


def test_session_of_another_source_port_is_never_a_false_match(wire):
    # the device ignored its sport filter and listed ports 40640 and 40641 for a flow from 50000
    result = wire({**UDP, "source_port": 50000}, session=SEEN)
    session = result["chain"]["session"]
    assert session["matching"] == 0 and session["sessions"] == [] and session["device_total"] == 2
    assert {"step": "session", "reason": "incomplete"} in result["missing"]
    assert result["verdict"] == "incomplete"
    assert not [f for f in result["findings"] if f["id"] == "F-FLOW-SESSION"]


def test_real_sessions_parser_filters_the_source_port_locally():
    assert t.sessions(SEEN, SRC, DST, 53, "udp")["matching"] == 2
    only = t.sessions(SEEN, SRC, DST, 53, "udp", 40641)
    assert only["matching"] == 1 and only["sessions"][0]["source_port"] == 40641 and only["complete"] is False
    assert t.sessions(ONE_SESSION, SRC, DST, 53, "udp", 40640)["complete"] is True
    assert t.sessions(ONE_SESSION, SRC, DST, 53, "udp", 40641)["matching"] == 0


def test_known_port_policy_denial_and_implicit_deny_use_the_given_port(wire):
    result = wire({**UDP, "source_port": 1234}, lookup=base.live("policy_nomatch"))
    assert result["verdict"] == "denied_by_policy" and _lookup_commands(wire.sent) == [LOOKUP % 1234]
    assert "source port 1234 " in result["findings"][-1]["fact"] or "source port 1234 " in result["findings"][0]["fact"]


def test_known_port_no_route_and_restore_failure_keep_their_meaning(wire, monkeypatch):
    result = wire({**UDP, "source_port": 4444}, route_dst=NO_ROUTE)
    assert result["verdict"] == "no_route" and _lookup_commands(wire.sent) == []

    def fail(*a, **k):
        raise diagnostics.RestoreUnverified("x")
    monkeypatch.setattr(diagnostics, "run", fail)
    result = wire({**UDP, "source_port": 4444}, route_dst=base.live("route_dst_internet"))
    assert result["ok"] is False and result["error_code"] == "restore_unverified"
    assert _lookup_commands(wire.sent) == [LOOKUP % 4444]


# ---- invalid values never reach a device ---------------------------------------------------------------------------
INVALID = [True, False, "40000", 0, -1, 65536, 40000.0, [40000], {"p": 1}]


@pytest.mark.parametrize("value", INVALID)
def test_invalid_source_port_is_refused_by_the_proxy_before_any_io(wire, value):
    with pytest.raises(proxy_module.ToolArgumentsError):
        proxy_module.Proxy._validate_tool_arguments("triage_flow", {"target": "x", **UDP, "source_port": value})
    emitted = []
    gateway = proxy_module.Proxy()
    gateway._emit = emitted.append
    assert gateway.request(c._request(1, "triage_flow", {"target": "device-a", **UDP, "source_port": value})) is None
    assert emitted and "error" in emitted[-1] and wire.sent == [] and Shell.created == []


@pytest.mark.parametrize("value", INVALID)
def test_invalid_source_port_is_refused_by_the_engine_before_any_io(audit_log, monkeypatch, value):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: pytest.fail("device contacted"))
    with pytest.raises(ValueError):
        t.validate(SRC, DST, 53, "udp", value)
    with pytest.raises(ValueError):
        engine.triage_flow(base._enrolled(*QUERIES), SRC, DST, 53, "udp", value)


def test_proxy_accepts_the_valid_range_and_none_and_icmp_has_no_port():
    check = proxy_module.Proxy._validate_tool_arguments
    for value in (None, 1, 40000, 65535):
        assert check("triage_flow", {"target": "x", **UDP, "source_port": value})["source_port"] == value
    assert "source_port" not in check("triage_flow", {"target": "x", **UDP})
    with pytest.raises(proxy_module.ToolArgumentsError):
        check("triage_flow", {"target": "x", "src": SRC, "dst": DST, "port": 1, "proto": "icmp", "source_port": 5})
    assert t.validate(SRC, DST, 53, "udp") == {**UDP, "source_port": None}
    assert t.validate(SRC, DST, 53, "udp", 7) == {**UDP, "source_port": 7}


def test_server_tool_takes_an_optional_source_port_and_keeps_the_old_order():
    import inspect
    from netops_helper import server
    function = getattr(server.triage_flow, "fn", server.triage_flow)
    parameters = list(inspect.signature(function).parameters.values())
    assert [p.name for p in parameters][:6] == ["target", "src", "dst", "port", "proto", "auth_context"]
    source_port, interface = parameters[6:]
    assert source_port.name == "source_port" and source_port.default is None
    assert source_port.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert interface.name == "interface" and interface.default is None
    assert interface.kind is inspect.Parameter.KEYWORD_ONLY
    assert all(p.default is inspect.Parameter.empty for p in parameters[:5])
