from __future__ import annotations

from collections import deque
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace

from netops_core.audit import Recorder
import pytest

from conftest import _target
import netops_helper.audit as audit
import netops_helper.engine as engine
from netops_helper import fortios_diagnostics as diagnostics
from netops_helper import proxy as proxy_module
from netops_helper import triage_flow as t

FIXTURES = Path(__file__).parent / "fixtures"
SRC = "192.0.2.11"
DST = "203.0.113.88"
NOW = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
# built at run time: the source privacy gate accepts multicast literals only where it lists them
MULTICAST = str(ipaddress.IPv4Address(0xE0000001))
FLOW = {"src": SRC, "dst": DST, "port": 443, "proto": "tcp"}


def live(name):
    return (FIXTURES / ("fortios_80f_802_flow_" + name + ".txt")).read_text()


SESSION_BLOCK = """session info: proto=6 proto_state=01 duration=477 expire=3599 timeout=3600 refresh_dir=both flags=00000000 socktype=0 sockport=0 av_idx=0 use=3
statistic(bytes/packets/allow_err): org=38568/624/1 reply=32404/623/1 tuples=2
orgin->sink: org pre->post, reply pre->post dev=13->3/3->13 gwy=198.51.100.1/192.0.2.184
hook=post dir=org act=snat 192.0.2.11:40640->203.0.113.88:443(198.51.100.2:40640)
hook=pre dir=reply act=dnat 203.0.113.88:443->198.51.100.2:40640(192.0.2.11:40640)
misc=0 policy_id=3 pol_uuid_idx=26053 auth_info=0 chk_client_info=0 vd=0
"""
NOOP_BLOCK = SESSION_BLOCK.replace("act=snat", "act=noop").replace("(198.51.100.2:40640)", "(0.0.0.0:0)")


def answer(text):
    return {"ok": True, "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest()}


def outputs(**changes):
    values = {"system_status": live("status"), "route_dst": live("route_dst_internet"),
              "route_src": live("route_src_lan"), "policy_lookup": live("policy_accept")}
    values.update(changes)
    return values


def run(values, flow=FLOW, sessions="not_run", refused=None):
    calls = []
    refused = refused or {}

    def read(query, parameters):
        key = query
        if query == "route_lookup":
            key = "route_dst" if parameters["address"] == flow["dst"] else "route_src"
        if query == "policy_lookup_ipv4":
            key = "policy_lookup"
        calls.append((query, parameters))
        if key in refused:
            return {"ok": False, "reason": refused[key]}
        return answer(values[key])

    session_calls = []

    def read_sessions(interface):
        session_calls.append(interface)
        return sessions

    ticks = iter(NOW + timedelta(seconds=n) for n in range(100))
    chosen = read_sessions if sessions != "not_run" else None
    return t.run(read, lambda: next(ticks), flow, "fw-1", chosen), calls, session_calls


def ids(items):
    return [item["id"] for item in items]


# ---- input checks -------------------------------------------------------------------------------------------------

def test_validate_returns_the_checked_flow():
    assert t.validate(SRC, DST, 443, "tcp") == FLOW
    assert t.validate(SRC, DST, 1, "icmp")["proto"] == "icmp"


@pytest.mark.parametrize("src,dst,port,proto", [
    ("192.0.2.011", DST, 443, "tcp"), (SRC, "8.8.8", 443, "tcp"), (SRC, DST, 0, "tcp"), (SRC, DST, 65536, "tcp"),
    (SRC, DST, True, "tcp"), (SRC, DST, "443", "tcp"), (SRC, DST, 443, "TCP"), (SRC, DST, 443, "sctp"),
    (SRC, DST, 443, 6), (SRC, MULTICAST, 443, "tcp"), ("0.0.0.0", DST, 443, "tcp"), (SRC, "127.0.0.1", 443, "tcp"),
    (SRC, "255.255.255.255", 443, "tcp"), (SRC, "fe80::1%eth0", 443, "tcp"), (SRC, "example.org", 443, "tcp"),
    (None, DST, 443, "tcp"), (SRC, DST, 443, None),
])
def test_validate_refuses_everything_that_is_not_a_checked_ipv4_or_ipv6_literal_flow(src, dst, port, proto):
    with pytest.raises(ValueError):
        t.validate(src, dst, port, proto)


@pytest.mark.parametrize("src,dst", [("2001:db8::1", DST), (SRC, "2001:db8::2"), ("2001:db8::1", "2001:db8::2"),
                                     ("::ffff:192.0.2.1", DST)])
def test_ipv6_is_reported_as_unsupported_before_any_device_contact(src, dst):
    assert t.validate(src, dst, 443, "tcp") == {"unsupported": "ipv6_not_supported"}


# ---- parsers on live 80F 8.0.2 output ------------------------------------------------------------------------------

def test_policy_lookup_reads_the_live_accept_and_the_implicit_deny():
    assert t.policy_lookup(live("policy_accept")) == {"matched": True, "policy_id": 3, "action": "accept",
                                                      "implicit": False}
    assert t.policy_lookup(live("policy_nomatch")) == {"matched": False, "policy_id": None, "action": "deny",
                                                       "implicit": True}
    assert t.policy_lookup(live("policy_err_src_route")) == {"error": "err_src_route"}


def test_policy_lookup_reads_an_explicit_deny_policy():
    assert t.policy_lookup(live("policy_accept").replace("accept", "deny"))["action"] == "deny"


@pytest.mark.parametrize("text", [
    "", "\n", live("policy_icmp_invalid"),
    live("policy_accept").replace("policy_action: accept", "policy_action: ipsec"),
    live("policy_accept").replace("matched policy_type: policy", "matched policy_type: proxy-policy"),
    live("policy_accept").replace("firewall proxy-policy id: 0", "firewall proxy-policy id: 4"),
    live("policy_accept").replace("firewall policy id: 3", "firewall policy id: 0"),
    live("policy_accept").replace("firewall policy id: 3", "firewall policy id: 03"),
    live("policy_accept") + "firewall policy id: 4\n",
    live("policy_accept") + "something new: 1\n",
    live("policy_accept").replace("policy_action: accept\n", ""),
    live("policy_nomatch").replace("sec_default_action: deny", "sec_default_action: accept"),
    live("policy_nomatch").replace("firewall policy id: 0", "firewall policy id: 3"),
    live("policy_nomatch") + "policy_action: accept\n",
    live("policy_err_src_route") + "firewall policy id: 3\n",
])
def test_policy_lookup_refuses_every_shape_it_has_not_measured(text):
    with pytest.raises(t.Unparsed):
        t.policy_lookup(text)


def test_sessions_parse_nat_and_ignore_the_source_port():
    result = t.sessions(SESSION_BLOCK + NOOP_BLOCK.replace("40640", "40641") + "total session: 2\n",
                        SRC, DST, 443, "tcp")
    assert result["complete"] is True and result["matching"] == 2 and result["device_total"] == 2
    assert result["sessions"][0] == {"policy_id": 3, "proto_state": "01", "duration_s": 477, "expire_s": 3599,
                                     "source_port": 40640,
                                     "nat": {"action": "snat", "translated": "198.51.100.2:40640"}}
    assert result["sessions"][1]["source_port"] == 40641 and result["sessions"][1]["nat"] is None


def test_sessions_filter_by_tuple_after_the_read_and_flag_a_device_that_ignored_its_filter():
    other = SESSION_BLOCK.replace("203.0.113.88:443", "203.0.113.84:443")
    result = t.sessions(SESSION_BLOCK + other + "total session: 2\n", SRC, DST, 443, "tcp")
    assert result["matching"] == 1 and result["device_total"] == 2 and result["complete"] is False
    result = t.sessions(SESSION_BLOCK + "total session: 1\n", SRC, DST, 443, "udp")
    assert result["matching"] == 0 and result["complete"] is False


def test_sessions_none_and_broken_texts():
    assert t.sessions("total session: 0\r\n", SRC, DST, 443, "tcp") == {
        "device_total": 0, "matching": 0, "sessions": [], "complete": True}
    for text in ("", "total session 0\n", "unrecognized session record\ntotal session: 0\n",
                 "total session: 0\nunrecognized session record\n", SESSION_BLOCK, SESSION_BLOCK + "total session: 1\ntotal session: 1\n"):
        with pytest.raises(t.Unparsed):
            t.sessions(text, SRC, DST, 443, "tcp")
    for broken in (SESSION_BLOCK.replace("misc=0 policy_id=3 ", ""), SESSION_BLOCK.replace("hook=post dir=org", "hook=post dir=x")):
        result = t.sessions(broken + "total session: 1\n", SRC, DST, 443, "tcp")
        assert result["complete"] is False and result["matching"] == 0


def test_sessions_report_at_most_five_but_count_all():
    result = t.sessions(SESSION_BLOCK * 7 + "total session: 7\n", SRC, DST, 443, "tcp")
    assert result["matching"] == 7 and len(result["sessions"]) == 5 and result["complete"] is True


UDP_FLOW = {"src": SRC, "dst": "203.0.113.53", "port": 53, "proto": "udp"}


def test_sessions_parse_the_live_80f_read_with_the_source_port_open():
    # `diagnose sys session list` after the filter src, dst, dport and proto (no sport) on a FortiGate-80F 8.0.2 build0251,
    # read with a read-only account from LAN-test to a resolver; two DNS sessions with different source ports
    result = t.sessions(live("session_seen"), SRC, "203.0.113.53", 53, "udp")
    assert result == {"device_total": 2, "matching": 2, "complete": True, "sessions": [
        {"policy_id": 3, "proto_state": "01", "duration_s": 84, "expire_s": 95, "source_port": 40640,
         "nat": {"action": "snat", "translated": "198.51.100.2:40640"}},
        {"policy_id": 3, "proto_state": "01", "duration_s": 84, "expire_s": 95, "source_port": 40641,
         "nat": {"action": "snat", "translated": "198.51.100.2:40641"}}]}


def test_sessions_parse_the_live_80f_empty_read():
    # the same filter for a flow without a session prints only the total
    assert live("session_none") == "total session: 0\n"
    assert t.sessions(live("session_none"), SRC, DST, 443, "tcp") == {
        "device_total": 0, "matching": 0, "sessions": [], "complete": True}


def test_unknown_text_around_an_empty_session_total_never_gives_allowed_no_session():
    unknown = {"ok": True, "text": "unrecognized session record\ntotal session: 0\n", "content_sha256": "c" * 64}
    result, _, _ = run(outputs(), sessions=unknown)
    assert result["verdict"] == "incomplete"
    assert result["missing"] == [{"step": "session", "reason": "unparsed",
                                  "first_lines": ["unrecognized session record", "total session: 0"]}]


def test_the_empty_read_as_the_helper_gets_it_from_the_80f_is_allowed_no_session():
    # the text that _flow_session_text hands over (measured on a FortiGate-80F 8.0.2 test unit,
    # filter without the source port) has no final line feed, so the one-line shape "total session: 0\n" never matched
    pty = live("session_none_pty")
    assert pty == "total session: 0"
    expected = {"device_total": 0, "matching": 0, "sessions": [], "complete": True}
    assert t.sessions(pty, SRC, DST, 443, "tcp") == expected
    result, _, _ = run(outputs(), sessions=answer(pty))
    assert result["verdict"] == "allowed_no_session" and result["missing"] == []
    assert result["chain"]["session"] == {"state": "read", **expected}


@pytest.mark.parametrize("text", ["total session: 0", "total session: 0\n", "\r\ntotal session: 0\r\n\r\n",
                                  "\n\n  total session: 0  \n\n", "FGT-lab # \ntotal session: 0\nFGT-lab # ",
                                  "FGT-lab (global) #\r\ntotal session: 0\r\nFGT-lab (global) # ",
                                  "FGT-lab $ \ntotal session: 0", "total session: 0\r"])
def test_prompts_carriage_returns_and_blank_lines_around_the_empty_total_are_ignored(text):
    assert t.sessions(text, SRC, DST, 443, "tcp")["complete"] is True


@pytest.mark.parametrize("text", ["", "\n", "FGT-lab # ", "total session: 1", "total session: 0\ntotal session: 0",
                                  "total session: 00", "Total session: 0", "warning\ntotal session: 0",
                                  "total session: 0\nwarning", "total session: 0 extra", "x # y\ntotal session: 0"])
def test_any_other_line_next_to_the_empty_total_stays_unparsed(text):
    with pytest.raises(t.Unparsed):
        t.sessions(text, SRC, DST, 443, "tcp")


def test_unparsed_session_text_reports_short_printable_first_lines():
    text = "\n" + "x" * 200 + "\n\x1b[31mred\x00\n\nthird\nfourth\n"
    result, _, _ = run(outputs(), sessions=answer(text))
    missing = [item for item in result["missing"] if item["step"] == "session"]
    assert missing == [{"step": "session", "reason": "unparsed", "first_lines": ["x" * 80, "?[31mred?", "third"]}]
    assert result["verdict"] == "incomplete"


def test_live_sessions_of_another_tuple_are_not_counted_and_flag_the_read():
    result = t.sessions(live("session_seen"), SRC, "203.0.113.53", 853, "udp")
    assert result["matching"] == 0 and result["device_total"] == 2 and result["complete"] is False
    result = t.sessions(live("session_seen"), SRC, "203.0.113.53", 53, "tcp")
    assert result["matching"] == 0 and result["complete"] is False


def test_live_session_text_gives_allowed_and_session_seen():
    result, _, session_calls = run(outputs(), UDP_FLOW, sessions=answer(live("session_seen")))
    assert result["verdict"] == "allowed_and_session_seen" and session_calls == ["LAN-test"]
    assert result["chain"]["session"]["matching"] == 2 and result["missing"] == []
    assert result["chain"]["session"]["sessions"][0]["nat"]["action"] == "snat"


def test_live_empty_session_text_gives_allowed_no_session():
    result, _, _ = run(outputs(), UDP_FLOW, sessions=answer(live("session_none")))
    assert result["verdict"] == "allowed_no_session" and result["missing"] == []
    assert result["chain"]["session"] == {"state": "read", "device_total": 0, "matching": 0, "sessions": [],
                                          "complete": True}


def test_live_session_text_that_was_not_filtered_to_the_flow_is_incomplete():
    result, _, _ = run(outputs(), {**UDP_FLOW, "dst": "203.0.113.99"}, sessions=answer(live("session_seen")))
    assert result["verdict"] == "incomplete" and {"step": "session", "reason": "incomplete"} in result["missing"]


# ---- the chain on the live fixtures --------------------------------------------------------------------------------

SEEN = {"ok": True, "text": SESSION_BLOCK + "total session: 1\n", "content_sha256": "a" * 64}
NONE = {"ok": True, "text": "total session: 0\n", "content_sha256": "b" * 64}


def test_allowed_flow_with_a_session_reads_the_documented_calls_and_reports_the_whole_chain():
    result, calls, session_calls = run(outputs(), sessions=SEEN)
    assert calls == [
        ("system_status", None), ("route_lookup", {"address": DST}), ("route_lookup", {"address": SRC}),
        ("policy_lookup_ipv4", {"src_ip": SRC, "src_port": "40000", "dst_ip": DST, "dst_port": "443",
                                "protocol": "6", "device": "LAN-test", "pol_type": "policy"})]
    assert session_calls == ["LAN-test"]
    assert result["verdict"] == "allowed_and_session_seen" and result["missing"] == []
    assert result["identity"] == {"product": "FortiGate-80F", "version": "8.0.2", "build": "0251"}
    assert result["checked"] == list(t.STEPS) and result["dataplane_simulated"] is False
    chain = result["chain"]
    assert chain["ingress"]["interface"] == "LAN-test" and chain["ingress"]["route"]["protocol"] == "connected"
    assert chain["egress"]["interfaces"] == ["LTE-1", "LTE-2", "wan1"]
    assert chain["policy"] == {"matched": True, "policy_id": 3, "action": "accept", "implicit": False,
                               "nat": "not_reported_by_lookup"}
    assert chain["session"]["matching"] == 1 and chain["session"]["sessions"][0]["nat"]["action"] == "snat"
    assert ids(result["findings"]) == ["F-FLOW-POLICY-ACCEPT", "F-FLOW-SESSION"]
    assert result["vantage"] == {"kind": "device_cli_lookup", "device": "fw-1", "packets_sent": False,
                                 "ingress_interface": "LAN-test", "ingress_inferred_from": "route to src",
                                 "policy_lookup_source_port": 40000}
    assert any("40000" in item for item in result["assumptions"]) and len(result["not_simulated"]) == 5
    assert result["next_steps"][0]["tool"] == "config_read" and "healthy" not in json.dumps(result)
    for finding in result["findings"]:
        assert finding["sources"] and all(s["content_sha256"] for s in finding["sources"])


def test_allowed_flow_without_a_session_is_allowed_no_session_only_after_a_complete_read():
    result, _, _ = run(outputs(), sessions=NONE)
    assert result["verdict"] == "allowed_no_session" and result["chain"]["session"]["matching"] == 0
    assert ids(result["findings"]) == ["F-FLOW-POLICY-ACCEPT"]


@pytest.mark.parametrize("reason,expected", [("not_enrolled", "not_enrolled"), ("timeout", "timeout"),
                                             ("surprise", "device_cli_error")])
def test_unread_session_never_gives_a_confident_verdict(reason, expected):
    result, _, _ = run(outputs(), sessions={"ok": False, "reason": reason})
    assert result["verdict"] == "incomplete" and {"step": "session", "reason": expected} in result["missing"]
    assert result["chain"]["policy"]["action"] == "accept"


def test_target_without_the_session_recipe_is_incomplete_not_allowed_no_session():
    result, _, session_calls = run(outputs())
    assert result["verdict"] == "incomplete" and session_calls == []
    assert result["missing"] == [{"step": "session", "reason": "not_enrolled"}]


def test_unparsed_or_incomplete_session_text_is_incomplete():
    result, _, _ = run(outputs(), sessions=answer("garbage\n"))
    assert result["verdict"] == "incomplete"
    assert {"step": "session", "reason": "unparsed", "first_lines": ["garbage"]} in result["missing"]
    result, _, _ = run(outputs(), sessions=answer(SESSION_BLOCK.replace("203.0.113.88:443", "203.0.113.84:443") + "total session: 1\n"))
    assert result["verdict"] == "incomplete" and {"step": "session", "reason": "incomplete"} in result["missing"]


def test_implicit_deny_is_denied_by_policy_and_reads_no_session():
    result, _, session_calls = run(outputs(policy_lookup=live("policy_nomatch")), sessions=SEEN)
    assert result["verdict"] == "denied_by_policy" and session_calls == []
    assert result["chain"]["policy"]["implicit"] is True and result["chain"]["session"] == {"state": "not_needed"}
    assert result["findings"][0]["fact"].startswith("no policy matched: implicit deny (lookup for source port 40000")
    assert result["next_steps"] == []


def test_explicit_deny_policy_is_denied_by_policy():
    result, _, _ = run(outputs(policy_lookup=live("policy_accept").replace("accept", "deny")))
    assert result["verdict"] == "denied_by_policy" and ids(result["findings"]) == ["F-FLOW-POLICY-DENY"]


def test_lan_to_the_local_network_uses_the_connected_route_beside_a_bgp_route():
    flow = {"src": SRC, "dst": "198.51.100.110", "port": 22, "proto": "tcp"}
    result, calls, _ = run(outputs(route_dst=live("route_dst_local")), flow, sessions=NONE)
    assert result["verdict"] == "allowed_no_session"
    assert result["chain"]["egress"]["interfaces"] == ["wan1"]
    assert calls[1] == ("route_lookup", {"address": "198.51.100.110"})
    assert calls[3][1]["dst_port"] == "22"


def test_flow_to_a_directly_connected_network_through_another_interface():
    flow = {"src": SRC, "dst": "203.0.113.2", "port": 22, "proto": "tcp"}
    result, _, _ = run(outputs(route_dst=live("route_dst_wan2"), policy_lookup=live("policy_nomatch")), flow)
    assert result["verdict"] == "denied_by_policy" and result["chain"]["egress"]["interfaces"] == ["wan2"]


def test_udp_uses_protocol_17():
    flow = {"src": SRC, "dst": DST, "port": 53, "proto": "udp"}
    _, calls, _ = run(outputs(), flow, sessions=NONE)
    assert calls[3][1]["protocol"] == "17" and calls[3][1]["dst_port"] == "53"


NO_ROUTE = "Routing table for VRF=default(0)\n% Network not in table\n"


def test_no_route_to_the_destination_wins_and_says_only_the_routing_table_was_read():
    result, calls, _ = run(outputs(route_dst=NO_ROUTE,
                                   policy_lookup="Error code: err_route\n"))
    assert result["verdict"] == "no_route" and ids(result["findings"]) == ["F-FLOW-NO-ROUTE-DST"]
    assert "policy routes were not evaluated" in result["findings"][0]["fact"]
    assert [call[0] for call in calls] == ["system_status", "route_lookup", "route_lookup"]
    assert result["chain"]["egress"] == {"route": None, "interfaces": []}
    assert result["next_steps"] == [{"tool": "ssh_read", "arguments": {
        "target": "fw-1", "platform": "fortinet", "query": "routing_table"}, "why": result["next_steps"][0]["why"]}]


@pytest.mark.parametrize("changes,refused,expected", [
    ({"route_src": "unexpected text\n"}, {}, {"step": "route_src", "reason": "unparsed"}),
    ({"route_src": " \n"}, {}, {"step": "route_src", "reason": "empty"}),
    ({}, {"route_src": "timeout"}, {"step": "route_src", "reason": "timeout"}),
    ({"route_src": NO_ROUTE}, {}, {"step": "policy_lookup", "reason": "ingress_unknown"}),
])
def test_a_missing_ingress_step_beats_no_route_but_keeps_the_missing_route_finding(changes, refused, expected):
    result, calls, _ = run(outputs(route_dst=NO_ROUTE, **changes), refused=refused)
    assert result["verdict"] == "incomplete" and expected in result["missing"]
    assert "F-FLOW-NO-ROUTE-DST" in ids(result["findings"])
    assert [call[0] for call in calls].count("policy_lookup_ipv4") == 0
    assert result["next_steps"][0]["arguments"]["query"] == "routing_table"


@pytest.mark.parametrize("changes,refused,expected", [
    ({"route_dst": "unexpected text\n"}, {}, {"step": "route_dst", "reason": "unparsed"}),
    ({}, {"route_dst": "truncated"}, {"step": "route_dst", "reason": "truncated"}),
])
def test_a_missing_destination_route_is_incomplete_whatever_else_was_read(changes, refused, expected):
    result, _, _ = run(outputs(**changes), sessions=NONE, refused=refused)
    assert result["verdict"] == "incomplete" and expected in result["missing"]
    assert "F-FLOW-NO-ROUTE-DST" not in ids(result["findings"])


def test_no_route_is_only_a_verdict_when_no_step_is_missing():
    result, _, _ = run(outputs(route_dst=NO_ROUTE))
    assert result["verdict"] == "no_route" and result["missing"] == []
    result, _, _ = run(outputs(route_dst=NO_ROUTE, route_src=NO_ROUTE))
    assert result["verdict"] == "incomplete" and ids(result["findings"]) == ["F-FLOW-NO-ROUTE-DST", "F-FLOW-NO-ROUTE-SRC"]
    assert result["missing"] == [{"step": "policy_lookup", "reason": "ingress_unknown"}]


def test_no_route_to_the_source_is_incomplete_because_reverse_path_filtering_is_not_known():
    result, calls, _ = run(outputs(route_src="Routing table for VRF=default(0)\n% Network not in table\n"))
    assert result["verdict"] == "incomplete" and ids(result["findings"]) == ["F-FLOW-NO-ROUTE-SRC"]
    assert [call[0] for call in calls] == ["system_status", "route_lookup", "route_lookup"]
    assert result["chain"]["policy"] is None and result["chain"]["ingress"]["interface"] is None
    assert result["missing"] == [{"step": "policy_lookup", "reason": "ingress_unknown"}]


def test_device_lookup_error_is_a_finding_and_never_a_verdict():
    result, _, _ = run(outputs(policy_lookup=live("policy_err_src_route")))
    assert result["verdict"] == "incomplete" and ids(result["findings"]) == ["F-FLOW-LOOKUP-ERROR"]
    assert "err_src_route" in result["findings"][0]["fact"]
    assert result["missing"] == [{"step": "policy_lookup", "reason": "device_cli_error"}]


def test_ecmp_ingress_over_two_interfaces_is_not_guessed():
    route = ("Routing table for VRF=default(0)\nRouting entry for 192.0.2.0/24\n"
             '  Known via "static", distance 1, metric 0, best\n'
             "  * vrf default(0) 192.0.2.1, via wan1, origin 2\n  * vrf default(0) 192.0.2.5, via wan2, origin 2\n")
    result, calls, _ = run(outputs(route_src=route))
    assert result["verdict"] == "incomplete" and [call[0] for call in calls].count("policy_lookup_ipv4") == 0
    assert {"step": "policy_lookup", "reason": "ingress_not_unique"} in result["missing"]


def test_same_interface_on_two_hops_is_one_ingress():
    route = ("Routing table for VRF=default(0)\nRouting entry for 192.0.2.0/24\n"
             '  Known via "static", distance 1, metric 0, best\n'
             "  * vrf default(0) 192.0.2.1, via wan1, origin 2\n  * vrf default(0) 192.0.2.5, via wan1, origin 2\n")
    result, calls, _ = run(outputs(route_src=route), sessions=NONE)
    assert calls[3][1]["device"] == "wan1" and result["verdict"] == "allowed_no_session"


def test_a_device_printed_ingress_of_the_wrong_shape_never_reaches_the_lookup():
    route = live("route_src_lan").replace("LAN-test", "x" * 30)
    result, calls, _ = run(outputs(route_src=route))
    assert [call[0] for call in calls].count("policy_lookup_ipv4") == 0 and result["verdict"] == "incomplete"


def test_icmp_reads_the_routes_only_because_the_policy_lookup_refuses_icmp_on_8_0_2():
    flow = {"src": SRC, "dst": DST, "port": 1, "proto": "icmp"}
    result, calls, session_calls = run(outputs(), flow, sessions=SEEN)
    assert [call[0] for call in calls] == ["system_status", "route_lookup", "route_lookup"] and session_calls == []
    assert result["verdict"] == "incomplete"
    assert {"step": "policy_lookup", "reason": "unsupported"} in result["missing"]
    assert {"step": "session", "reason": "unsupported"} in result["missing"]
    assert result["vantage"]["policy_lookup_source_port"] is None
    result, _, _ = run(outputs(route_dst=NO_ROUTE), flow)
    assert result["verdict"] == "incomplete" and ids(result["findings"]) == ["F-FLOW-NO-ROUTE-DST"]
    assert {"step": "policy_lookup", "reason": "unsupported"} in result["missing"]


@pytest.mark.parametrize("step,reason", [("route_dst", "timeout"), ("route_src", "device_cli_error"),
                                         ("policy_lookup", "permission_denied")])
def test_a_failed_read_makes_the_verdict_incomplete(step, reason):
    result, _, _ = run(outputs(), sessions=NONE, refused={step: reason})
    assert result["verdict"] == "incomplete" and {"step": step, "reason": reason} in result["missing"]


@pytest.mark.parametrize("step", ["route_dst", "route_src", "policy_lookup"])
def test_an_unparsed_or_empty_read_makes_the_verdict_incomplete(step):
    result, _, _ = run(outputs(**{step: "unexpected text\n"}), sessions=NONE)
    assert result["verdict"] == "incomplete" and {"step": step, "reason": "unparsed"} in result["missing"]
    result, _, _ = run(outputs(**{step: " \n"}), sessions=NONE)
    assert result["verdict"] == "incomplete" and {"step": step, "reason": "empty"} in result["missing"]


def test_a_destination_route_failure_does_not_hide_an_allowed_policy():
    result, _, _ = run(outputs(), sessions=SEEN, refused={"route_dst": "timeout"})
    assert result["verdict"] == "incomplete" and result["chain"]["policy"]["action"] == "accept"


@pytest.mark.parametrize("status", [
    "Version: FortiGate-60F v7.6.8,build3744,260115 (GA.M)\nVirtual domain configuration: disable\n",
    "Version: FortiGate-80F v8.0.2,build0252,260928 (GA.F)\nVirtual domain configuration: disable\n",
    live("status").replace("Virtual domain configuration: disable", "Virtual domain configuration: multiple"),
    "no version here\n",
])
def test_other_identities_and_vdom_modes_are_refused_after_the_identity_read(status):
    calls = []

    def read(query, parameters):
        calls.append(query)
        return answer(status)

    with pytest.raises(t.UnsupportedPlatform, match="config_platform_not_supported"):
        t.run(read, lambda: NOW, FLOW, "fw-1")
    assert calls == ["system_status"]


def test_failed_identity_read_is_not_supported():
    with pytest.raises(t.UnsupportedPlatform):
        t.run(lambda q, p: {"ok": False, "reason": "timeout"}, lambda: NOW, FLOW, "fw-1")


# ---- engine and proxy ----------------------------------------------------------------------------------------------

COMMANDS = {
    "get system status": "system_status",
    "get router info routing-table details " + DST: "route_dst",
    "get router info routing-table details " + SRC: "route_src",
    "diagnose firewall iprope lookup %s 40000 %s 443 6 LAN-test policy" % (SRC, DST): "policy_lookup",
}


@pytest.fixture()
def audit_log(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    return path


def _enrolled(*queries, inventory=None):
    return replace(_target("fortinet", "system_status"), enabled_queries=tuple(queries),
                   read_inventory=inventory or {})


QUERIES = ("system_status", "route_lookup", "policy_lookup_ipv4")


def test_engine_reads_with_values_that_are_not_in_the_inventory_and_audits_the_flow(audit_log, monkeypatch):
    sent = []
    values = outputs()

    def device(auth, platform, command, **_):
        sent.append(command)
        return 0, values[COMMANDS[command]]

    monkeypatch.setattr(engine, "read_from_device", device)
    result = engine.triage_flow(_enrolled(*QUERIES), SRC, DST, 443, "tcp")
    assert sent == list(COMMANDS)
    assert result["ok"] is True and result["target"] == "wire-test" and result["flow"] == FLOW
    assert result["verdict"] == "incomplete" and result["missing"] == [{"step": "session", "reason": "not_enrolled"}]
    records = [json.loads(line) for line in audit_log.read_text().splitlines()]
    events = [r["event"] for r in records]
    assert events.count("triage_flow_read") == 8 and events[0] == events[-1] == "triage_flow"
    outer = [r for r in records if r["event"] == "triage_flow"]
    assert all(r["source_address"] == SRC and r["destination_address"] == DST and r["port"] == 443
               and r["protocol"] == 6 for r in outer)
    assert "untrusted_device_output" not in result


def test_engine_keeps_the_catalogue_validation_of_every_value(audit_log, monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    with pytest.raises(ValueError):
        engine.triage_flow(_enrolled(*QUERIES), "192.0.2.11; show", DST, 443, "tcp")
    values = outputs(route_src=live("route_src_lan").replace("LAN-test", "wan 1 ; x"))
    sent = []

    def device(auth, platform, command, **_):
        sent.append(command)
        return 0, values[COMMANDS.get(command, "policy_lookup")] if command in COMMANDS else ""

    monkeypatch.setattr(engine, "read_from_device", device)
    result = engine.triage_flow(_enrolled(*QUERIES), SRC, DST, 443, "tcp")
    assert not any("iprope" in command for command in sent) and result["verdict"] == "incomplete"


def test_engine_does_not_widen_the_inventory_for_later_calls(audit_log, monkeypatch):
    auth = _enrolled(*QUERIES, inventory={"addresses": ("192.0.2.1",)})
    values = outputs()
    monkeypatch.setattr(engine, "read_from_device", lambda a, p, command, **_: (0, values[COMMANDS[command]]))
    engine.triage_flow(auth, SRC, DST, 443, "tcp")
    assert auth.read_inventory == {"addresses": ("192.0.2.1",)}
    with pytest.raises(ValueError, match="not enrolled"):
        engine.ssh_read(auth, "fortinet", "route_lookup", {"address": SRC}, 0, 16000)


def test_engine_maps_a_disabled_query_to_permission_denied(audit_log, monkeypatch):
    values = outputs()
    monkeypatch.setattr(engine, "read_from_device", lambda a, p, command, **_: (0, values[COMMANDS[command]]))
    result = engine.triage_flow(_enrolled("system_status", "route_lookup"), SRC, DST, 443, "tcp")
    assert {"step": "policy_lookup", "reason": "permission_denied"} in result["missing"]
    assert result["verdict"] == "incomplete"


def test_engine_ipv6_is_unsupported_without_a_device_read(audit_log, monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    result = engine.triage_flow(_enrolled(*QUERIES), "2001:db8::1", "2001:db8::2", 443, "tcp")
    assert result == {"ok": False, "target": "wire-test", "verdict": "unsupported", "reason": "ipv6_not_supported",
                      "detail": "triage_flow reads IPv4 flows only; no device was contacted"}


@pytest.mark.parametrize("args", [(SRC, DST, 0, "tcp"), (SRC, DST, 443, "sctp"), ("x", DST, 443, "tcp")])
def test_engine_refuses_bad_input_before_device_contact(audit_log, monkeypatch, args):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    with pytest.raises(ValueError):
        engine.triage_flow(_enrolled(*QUERIES), *args)


def test_engine_refuses_other_platforms_before_device_contact(audit_log, monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", lambda *a, **k: pytest.fail("device contacted"))
    with pytest.raises(ValueError, match="unsupported_platform"):
        engine.triage_flow(_target("fortiadc", "system_status"), SRC, DST, 443, "tcp")


def _session_auth(recipes=("sessions",), interfaces=("LAN-test",)):
    return _enrolled(*QUERIES, inventory={"diagnostic_recipes": tuple(recipes), "interfaces": tuple(interfaces)})


def test_session_read_needs_the_recipe_and_the_ingress_interface_enrolled(monkeypatch):
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: pytest.fail("device contacted"))
    for auth in (_session_auth(recipes=()), _session_auth(interfaces=("wan1",)), _enrolled(*QUERIES)):
        assert engine._flow_session_text(auth, FLOW, "LAN-test") == {"ok": False, "reason": "not_enrolled"}
    no_status = replace(_session_auth(), enabled_queries=("route_lookup",))
    assert engine._flow_session_text(no_status, FLOW, "LAN-test") == {"ok": False, "reason": "permission_denied"}


def test_session_read_sets_a_filter_without_the_source_port(monkeypatch):
    from contextlib import nullcontext
    import netops_core.target_lock
    seen = {}

    def fake_run(shell, recipe, address, interface, count, timeout, vdom, **kwargs):
        seen.update(recipe=recipe, address=address, interface=interface, **kwargs)
        return SESSION_BLOCK + "total session: 1\n", False, ("FortiGate-80F", "8.0.2", "0251"), "root"

    monkeypatch.setattr(diagnostics, "run", fake_run)
    monkeypatch.setattr(netops_core.target_lock, "target_lock", lambda fingerprint: nullcontext())
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: ["192.0.2.10"])
    monkeypatch.setattr(engine, "host_key_line", lambda *a: "pinned")
    monkeypatch.setattr(engine, "_paced_connection", lambda *a: nullcontext())
    monkeypatch.setattr(engine, "DeviceCredential", lambda auth: None)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda session: session)
    monkeypatch.setattr(engine.core_session, "Session", lambda *a, **k: nullcontext(SimpleNamespace(close=lambda: None)))
    out = engine._flow_session_text(_session_auth(), FLOW, "LAN-test")
    assert out["ok"] is True and out["text"].endswith("total session: 1\n")
    assert seen["recipe"] == "sessions" and seen["address"] == DST and seen["interface"] == "LAN-test"
    assert seen["source_address"] == SRC and "source_port" not in seen and seen["any_source_port"] is True
    assert seen["destination_port"] == 443 and seen["protocol"] == 6
    monkeypatch.setattr(diagnostics, "run", lambda *a, **k: ("", True, None, "root"))
    assert engine._flow_session_text(_session_auth(), FLOW, "LAN-test") == {"ok": False, "reason": "timeout"}

    def refuse(*a, **k):
        raise diagnostics.UnsupportedPlatform("x")

    monkeypatch.setattr(diagnostics, "run", refuse)
    assert engine._flow_session_text(_session_auth(), FLOW, "LAN-test") == {"ok": False, "reason": "unsupported"}
    monkeypatch.setattr(diagnostics, "run", lambda *a, **k: 1 / 0)
    assert engine._flow_session_text(_session_auth(), FLOW, "LAN-test") == {"ok": False, "reason": "device_cli_error"}


def _patched_session_read(monkeypatch, raw):
    from contextlib import nullcontext
    import netops_core.target_lock
    monkeypatch.setattr(diagnostics, "run", lambda *a, **k: (raw, False, ("FortiGate-80F", "8.0.2", "0251"), "root"))
    monkeypatch.setattr(netops_core.target_lock, "target_lock", lambda fingerprint: nullcontext())
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: ["192.0.2.10"])
    monkeypatch.setattr(engine, "host_key_line", lambda *a: "pinned")
    monkeypatch.setattr(engine, "_paced_connection", lambda *a: nullcontext())
    monkeypatch.setattr(engine, "DeviceCredential", lambda auth: None)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda session: session)
    monkeypatch.setattr(engine.core_session, "Session", lambda *a, **k: nullcontext(SimpleNamespace(close=lambda: None)))


def test_the_session_text_measured_on_the_80f_gives_allowed_no_session_through_the_engine_path(monkeypatch):
    _patched_session_read(monkeypatch, live("session_none_pty"))
    answer_from_engine = engine._flow_session_text(_session_auth(), FLOW, "LAN-test")
    assert answer_from_engine["ok"] is True and answer_from_engine["text"] == "total session: 0"
    result, _, _ = run(outputs(), sessions=answer_from_engine)
    assert result["verdict"] == "allowed_no_session" and result["missing"] == []


def test_unknown_session_text_is_redacted_before_its_first_lines_are_reported(monkeypatch):
    secret = _session_auth().secret
    _patched_session_read(monkeypatch, "unexpected banner " + secret + "\ntotal session: 0")
    answer_from_engine = engine._flow_session_text(_session_auth(), FLOW, "LAN-test")
    result, _, _ = run(outputs(), sessions=answer_from_engine)
    lines = [item for item in result["missing"] if item["step"] == "session"][0]["first_lines"]
    assert secret not in json.dumps(result) and lines[1] == "total session: 0" and lines[0].startswith("unexpected banner")


def test_the_sessions_recipe_leaves_the_source_port_open_only_when_asked():
    kwargs = dict(source_address=SRC, destination_port=443, protocol=6)
    diagnostics.validate("sessions", DST, "LAN-test", 8, 5, 16000, any_source_port=True, **kwargs)
    for bad in ({"source_port": 1}, {"source_address": None}, {"destination_port": None}, {"protocol": None}):
        with pytest.raises(ValueError):
            diagnostics.validate("sessions", DST, "LAN-test", 8, 5, 16000, any_source_port=True, **{**kwargs, **bad})
    with pytest.raises(ValueError):
        diagnostics.validate("flow", DST, "LAN-test", 8, 5, 16000, any_source_port=True, **kwargs)
    with pytest.raises(ValueError, match="complete TCP or UDP tuple"):
        diagnostics.validate("sessions", DST, "LAN-test", 8, 5, 16000, **kwargs)


class FakeShell:
    prompt = b""

    def __init__(self):
        self.commands = []

    def command(self, text, timeout=None):
        self.commands.append(text)
        if text == "get system status":
            return live("status")
        if text.startswith("show full-configuration system interface"):
            return 'config system interface\n edit "LAN-test"\n set vdom "root"\n next\nend\n'
        if text.startswith("diagnose netlink interface list"):
            return "if=LAN-test family=00 type=1\n"
        if text == "diagnose sys session filter":
            return ("session filter:\n" + "".join("\t%s: any\n" % name for name in (
                "vd", "sintf", "dintf", "proto", "proto-state", "source ip", "NAT'd source ip", "dest ip",
                "source port", "NAT'd source port", "dest port", "policy id", "ngfw id", "expire", "duration",
                "state1", "state2")))
        return ""

    def listen(self, timeout):
        return ""


def test_the_recipe_run_sends_no_sport_selector_without_a_source_port(monkeypatch):
    shell = FakeShell()
    monkeypatch.setattr(diagnostics, "_bounded", lambda s, command, timeout, grace=3: ("total session: 0\n", False))
    diagnostics.run(shell, "sessions", DST, "LAN-test", 8, 5, None, source_address=SRC, destination_port=443,
                    protocol=6, any_source_port=True)
    selectors = [c for c in shell.commands if c.startswith("diagnose sys session filter ") and "clear" not in c]
    assert selectors == ["diagnose sys session filter src " + SRC, "diagnose sys session filter dst " + DST,
                         "diagnose sys session filter dport 443", "diagnose sys session filter proto 6"]
    assert shell.commands[-2:] == ["diagnose sys session filter clear", "diagnose sys session filter"]


def test_proxy_validates_and_scopes_the_tool():
    Proxy = proxy_module.Proxy
    args = {"target": "fg", "src": SRC, "dst": DST, "port": 443, "proto": "tcp"}
    assert Proxy._validate_tool_arguments("triage_flow", dict(args)) == args
    assert Proxy._validate_tool_arguments("triage_flow", {**args, "src": "2001:db8::1"})["src"] == "2001:db8::1"
    for bad in ({"target": "fg"}, {**args, "extra": 1}, {**args, "port": 0}, {**args, "port": "443"},
                {**args, "port": True}, {**args, "proto": "sctp"}, {**args, "src": "10.0.0.256"},
                {**args, "dst": MULTICAST}, {**args, "src": 5}):
        with pytest.raises(proxy_module.ToolArgumentsError):
            Proxy._validate_tool_arguments("triage_flow", bad)

    def section(platform="fortinet", queries=QUERIES):
        return SimpleNamespace(egress={}, catalog_platform=lambda: platform, enabled_queries=queries,
                               read_inventory={})

    Proxy._authorize_tool("triage_flow", args, None, section())
    for changed in (section(platform="fortiadc"), section(queries=("system_status", "route_lookup")),
                    section(queries=("system_status", "policy_lookup_ipv4")),
                    section(queries=("route_lookup", "policy_lookup_ipv4"))):
        with pytest.raises(proxy_module.PolicyScopeError):
            Proxy._authorize_tool("triage_flow", args, None, changed)


def test_next_steps_are_valid_proxy_calls_for_the_target():
    Proxy = proxy_module.Proxy
    steps = []
    result, _, _ = run(outputs(route_dst=NO_ROUTE))
    steps += result["next_steps"]
    result, _, _ = run(outputs(), sessions=NONE)
    steps += result["next_steps"]
    assert [step["tool"] for step in steps] == ["ssh_read", "config_read"]
    for step in steps:
        required, optional = proxy_module.TOOL_ARGUMENT_SCHEMAS[step["tool"]]
        assert required <= set(step["arguments"]) <= required | optional
        assert step["arguments"]["target"] == "fw-1"
        assert Proxy._validate_tool_arguments(step["tool"], dict(step["arguments"])) == step["arguments"]
    ssh_read, config_read = steps

    def section(**inventory):
        return SimpleNamespace(egress={"tcp_ports": [22], "tcp_port_ranges": []}, catalog_platform=lambda: "fortinet",
                               enabled_queries={"routing_table"}, read_inventory=inventory,
                               ssh_platform="fortinet")

    Proxy._authorize_tool("ssh_read", ssh_read["arguments"], SimpleNamespace(port=22), section())
    Proxy._authorize_tool("config_read", config_read["arguments"], SimpleNamespace(port=22),
                          section(config_access=["read"]))
    with pytest.raises(proxy_module.PolicyScopeError):
        Proxy._authorize_tool("config_read", config_read["arguments"], SimpleNamespace(port=22), section())


def test_proxy_charges_the_planned_reads(monkeypatch):
    proxy = proxy_module.Proxy()
    monkeypatch.setattr(proxy_module.time, "monotonic", lambda: 100.0)
    limit = {"requests": 30, "window_seconds": 60}
    proxy.rate_history["fg"] = deque([90.0] * 26)
    with pytest.raises(proxy_module.RateLimitError):
        proxy._consume_rate_limit("fg", limit, proxy_module.TRIAGE_READS["triage_flow"])
    proxy.rate_history["fg"] = deque([90.0] * 25)
    proxy._consume_rate_limit("fg", limit, proxy_module.TRIAGE_READS["triage_flow"])
    assert len(proxy.rate_history["fg"]) == 30
    assert proxy_module.TRIAGE_FLOW_READS == t.PLANNED_READS == 5


@pytest.mark.parametrize("error,code", [(TimeoutError("synthetic"), "timeout"),
                                        (OSError("synthetic"), "ssh_unavailable")])
def test_engine_identity_transport_failure_is_incomplete(monkeypatch, error, code):
    from conftest import _target
    from netops_helper import engine
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    def failed(*args, **kwargs):
        raise error
    monkeypatch.setattr(engine, "read_from_device", failed)
    result = engine.triage_flow(_target("fortinet", "system_status"),
                                "192.0.2.10", "198.51.100.10", 443, "tcp")
    assert result["ok"] is False
    assert result["error_code"] == code
    assert result["failed_step"] == "system_status"
    assert result["verdict"] == "incomplete"


@pytest.mark.parametrize("exception,reason", [(diagnostics.RestoreUnverified, "restore_unverified"),
                                               (diagnostics.ScopeRefused, "scope_refused")])
def test_session_cleanup_and_scope_failures_reach_the_final_tool_result(monkeypatch, exception, reason):
    _patched_session_read(monkeypatch, "")
    def fail(*a, **k):
        raise exception("untrusted exception text")
    monkeypatch.setattr(diagnostics, "run", fail)
    answer_from_engine = engine._flow_session_text(_session_auth(), FLOW, "LAN-test")
    assert answer_from_engine["reason"] == reason and answer_from_engine["failed_step"] == "session"
    result, _, _ = run(outputs(), sessions=answer_from_engine)
    assert result["ok"] is False and result["error_code"] == reason and result["failed_step"] == "session"
    assert {"step": "session", "reason": reason} in result["missing"]
    assert result["chain"]["session"]["state"] == reason
    assert "untrusted exception text" not in json.dumps(result)
    if reason == "restore_unverified":
        assert "diagnose sys session filter clear" in result["error"]
