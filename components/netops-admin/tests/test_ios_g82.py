"""1.0.12 G82 (XE-M029 IPv4/IPv6 ACL rules and their order, XE-M030 attachment to an interface and direction) on IOL XE
17.18.2 over real anonymised answers.

The fixtures (fixtures/iosxe_g82, PROVENANCE.md) were captured on the GNS3 router d-iolxe (port 2257) by independent CLI
sessions of the write account and the privilege-1 check account (task netops-20261119-639): the test ACLs
NETOPS-G82-* were created, changed, attached to Ethernet0/2 (VRF blue link) and removed again. G82Ios (fake_iosxe_acl.py)
is FakeIos with that running configuration; it changes the ACL and interface lines like the measured device.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import request_bytes
from enrollment_helpers import certify
from fake_ios import FakeIos
from fake_iosxe_acl import G82Ios, answer, body, fixture
from test_ios import make_runtime

from netops_admin import engine, exec_ios, execute, ios, ios_acl
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FW = "17.18.2"
ACCOUNTS = ("user01", "user02")
BASELINE = fixture("admin-show-running-config__baseline.txt")
ACLS = fixture("admin-show-running-config__acls.txt")
BOUND = fixture("admin-show-running-config__bound.txt")
# DERIVED: the measured -V4B holds a non-contiguous wildcard (203.0.113.176 0.0.0.254) and the measured -V6 an ICMP type
# (icmp ... echo-reply); both are outside the profile and stay in ACLS/BOUND as they are. Without those two lines the
# ACLs are inside the profile: ACLS_OK/BOUND_OK are the measured configurations minus exactly these two lines.
V4B_WILDCARD = " 50 permit ip 203.0.113.176 0.0.0.254 any\n"
V6_ECHO = " sequence 110 permit icmp any any echo-reply\n"
ACLS_OK = ACLS.replace(V4B_WILDCARD, "").replace(V6_ECHO, "")
BOUND_OK = BOUND.replace(V4B_WILDCARD, "").replace(V6_ECHO, "")
assert len(ACLS_OK) == len(ACLS) - len(V4B_WILDCARD) - len(V6_ECHO) and len(BOUND_OK) < len(BOUND)

V4_RULES = ("10 permit tcp 203.0.113.32/27 host 203.0.113.39 eq 22, 20 permit udp any any eq 53, 30 permit icmp any any, "
            "40 deny ip host 203.0.113.41 any, 50 permit tcp any any eq 80, 60 permit tcp any any eq 443, "
            "70 permit tcp any any eq 8080, 80 permit udp any any eq 123, 90 permit tcp any any eq 179, "
            "100 permit tcp any any eq 25, 110 permit tcp any any eq 23, 120 permit tcp any any eq 21, "
            "130 permit udp any any eq 161, 140 permit udp any any eq 514, 150 permit tcp 192.0.2.0/30 any, "
            "160 permit tcp any any eq 8443, 170 permit tcp any any eq 67, 180 permit udp any any eq 69, "
            "190 permit udp any any eq 67")
V6_RULES = ("10 permit tcp 2001:db8:69::/64 host 2001:db8:69::7 eq 22, 20 permit udp any any eq 53, "
            "30 permit icmp any any, 40 deny ipv6 host 2001:db8:69::9 any, 50 permit ipv6 2001:db8:1::/48 any, "
            "60 permit tcp any any eq 80, 80 permit ipv6 any any, 90 permit tcp host 2001:db8:69::1 any, "
            "100 permit ipv6 any 2001:db8:69::/64")
PORT = "Ethernet0/2"
IN4, OUT4, IN6, OUT6 = ("%s:ipv4:in" % PORT, "%s:ipv4:out" % PORT, "%s:ipv6:in" % PORT, "%s:ipv6:out" % PORT)
DEVICE = type("Device", (), {"platform": "iosxe", "firmware": FW, "protected": {}})()


def steps(record):
    return [step["step"] + (": %s" % (step["detail"],) if step.get("detail") else "") for step in record["steps"]]


def names(record):
    return [step["step"] for step in record["steps"]]


def request(table, key, op="update", changes=None, request_id="req-g82-0001", **more):
    return parse_request(request_bytes(table=table, op=op, key=key, changes=changes or {},
                                       request_id=request_id, **more))


def acl(key, op="update", changes=None, **more):
    return request(ios_acl.ACL, key, op, changes, **more)


def bind(key, acl_name, **more):
    return request(ios_acl.BINDING, key, "update", {"acl": acl_name}, **more)


def plan(req, text=ACLS_OK, protected=None):
    return engine.build_plan("iosxe", text.encode(), req, firmware=FW, protected=protected)


def stable(lines):
    return [line for line in lines if not line.startswith(ios.VOLATILE_HEADER)]


def runtime(tmp_path, device, protected=None):
    rt = make_runtime(tmp_path, device, accounts=ACCOUNTS)
    rt.config.limits["changes_per_device_per_hour"] = 60
    if protected:
        rt.config.devices["lab-ios"].protected.update(protected)
        certify(rt, device, "lab-ios")
    return rt


def approved(rt, req):
    preview = execute.preview(rt, "lab-ios", req)
    assert preview["result"] == "ready", preview
    return preview["plan_sha256"]


def apply(rt, req):
    return execute.apply(rt, "lab-ios", req, expected_plan_sha256=approved(rt, req))


def active(text):
    """The state of an ACL or an attachment as the profile sees it."""
    snapshot = ios.load(text, FW)
    snapshot.platform = "iosxe"
    return snapshot


# ---- the measured configurations and the profile gate ----

def test_the_measured_acls_are_read_as_canonical_rules():
    entries = active(ACLS_OK).entries(ios_acl.ACL)
    # printed names (domain, www, bgp, tftp, bootps, ...) and wildcards are the numbers and prefixes of the profile
    assert entries["ipv4:NETOPS-G82-V4"].attributes == {"rules": V4_RULES}
    assert entries["ipv6:NETOPS-G82-V6"].attributes == {"rules": V6_RULES}
    # an IPv4 ACL without rules stays configured, with the header only
    assert entries["ipv4:NETOPS-G82-V4C"].attributes == {} and entries["ipv4:NETOPS-G82-V4C"].unsupported == []
    assert entries["ipv4:G69-PBR-ACL"].attributes == {"rules": "10 permit ip any 203.0.113.96/27"}
    assert not any(name.endswith("NETOPS-G82-NEW") for name in entries)
    assert not [name for name in active(BASELINE).entries(ios_acl.ACL) if "G82" in name]


def test_rules_outside_the_profile_are_marked_not_dropped():
    entries = active(ACLS).entries(ios_acl.ACL)
    assert entries["ipv4:NETOPS-G82-V4B"].unsupported == ["unsupported ACL rules or settings"]
    assert entries["ipv6:NETOPS-G82-V6"].unsupported == ["unsupported ACL rules or settings"]
    assert "rules" not in entries["ipv4:NETOPS-G82-V4B"].attributes
    for text, what in ((ACLS_OK.replace(" 30 permit icmp any any\n", " 30 permit icmp any any echo\n"), "icmp type"),
                       (ACLS_OK.replace(" 40 deny ip host 203.0.113.41 any\n", " 40 deny ip host 203.0.113.41 any log\n"), "log"),
                       (ACLS_OK.replace(" 50 permit tcp any any eq www\n", " 50 permit tcp any any range 80 90\n"), "range"),
                       (ACLS_OK.replace(" 60 permit tcp any any eq 443\n", " remark web\n 60 permit tcp any any eq 443\n"),
                        "remark")):
        assert active(text).entries(ios_acl.ACL)["ipv4:NETOPS-G82-V4"].unsupported, what
    standard = ACLS_OK.replace("ip access-list extended NETOPS-G82-V4C\n", "ip access-list standard NETOPS-G82-V4C\n")
    assert active(standard).entries(ios_acl.ACL)["ipv4:NETOPS-G82-V4C"].unsupported == ["standard ACL"]


def test_the_attachments_of_the_measured_configuration():
    entries = active(BOUND_OK).entries(ios_acl.BINDING)
    assert {key: entry.attributes for key, entry in entries.items() if entry.attributes} == {
        IN4: {"acl": "NETOPS-G82-V4"}, OUT4: {"acl": "NETOPS-G82-V4B"},
        IN6: {"acl": "NETOPS-G82-V6"}, OUT6: {"acl": "NETOPS-G82-V6"}}
    assert entries["Ethernet0/3:ipv4:in"].attributes == {} and "Loopback0:ipv4:in" not in entries
    assert active(ACLS_OK).entries(ios_acl.BINDING)[IN4].attributes == {}


def test_the_named_ports_of_the_profile_are_exactly_the_measured_ones():
    measured = json.loads((Path(__file__).parent / "fixtures" / "iosxe_g82" / "ports-measured.json").read_text())
    assert ios_acl.XE_SERVICES["tcp"] == {**measured["v4-tcp"], **measured["v6-tcp"]}
    assert ios_acl.XE_SERVICES["udp"] == {**measured["v4-udp"], **measured["v6-udp"]}
    # the device prints udp 67 as bootps and tcp 67 as 67: the numbers are the canonical form
    assert measured["v4-udp"]["bootps"] == 67 and "bootps" not in measured["v4-tcp"]


# ---- the answers of the check account ----

def observe_acl(text, key):
    return ios_acl.observe_acl(text, key, xe=True)


def observe_binding(text, key):
    return ios_acl.observe_binding(text, key, xe=True)


def test_check_account_answers_of_the_measured_device():
    assert observe_acl(fixture("ro-show-ip-access-lists-NETOPS-G82-V4__acls.txt"), "ipv4:NETOPS-G82-V4") == {
        "rules": V4_RULES}
    assert observe_acl(fixture("ro-show-ip-access-lists-NETOPS-G82-V4C__acls.txt"), "ipv4:NETOPS-G82-V4C") == {}
    assert observe_acl(fixture("ro-show-ip-access-lists-NOPE-X__acls.txt"), "ipv4:NOPE-X") is None
    assert observe_acl(fixture("ro-show-ipv6-access-list-NOPE-X__acls.txt"), "ipv6:NOPE-X") is None
    # the hit counter of a rule is not part of the state (measured on the existing G69-PBR-ACL: 5824 matches)
    assert observe_acl(fixture("ro-show-ip-access-lists-G69-PBR-ACL.txt"), "ipv4:G69-PBR-ACL") == {
        "rules": "10 permit ip any 203.0.113.96/27"}
    v6 = fixture("ro-show-ipv6-access-list-NETOPS-G82-V6__acls.txt")
    assert v6.count("sequence") == 10 and "echo-reply sequence 110" in v6
    with pytest.raises(Rejected) as caught:  # the measured answer holds the rule outside the profile
        observe_acl(v6, "ipv6:NETOPS-G82-V6")
    assert caught.value.reason_codes == ["ios_acl_readback_unreadable"]
    assert observe_acl(v6.replace("    permit icmp any any echo-reply sequence 110\n", ""),
                               "ipv6:NETOPS-G82-V6") == {"rules": V6_RULES}
    assert observe_acl(v6.replace("eq 22 sequence 10", "eq 22 (7 matches) sequence 10").replace(
        "    permit icmp any any echo-reply sequence 110\n", ""), "ipv6:NETOPS-G82-V6") == {"rules": V6_RULES}


@pytest.mark.parametrize("text,key", [
    ('\n\nLine has invalid autocommand "show ip access-lists NETOPS-G82-V4"', "ipv4:NETOPS-G82-V4"),
    (fixture("ro-show-ip-access-lists-NETOPS-G82-V4__acls.txt").replace("Extended IP access list NETOPS-G82-V4",
                                                                       "Extended IP access list OTHER"), "ipv4:NETOPS-G82-V4"),
    (fixture("ro-show-ip-access-lists-NETOPS-G82-V4__acls.txt").replace("Extended", "Standard"), "ipv4:NETOPS-G82-V4"),
    (fixture("ro-show-ip-access-lists-NETOPS-G82-V4__acls.txt") + "--More--", "ipv4:NETOPS-G82-V4"),
    (fixture("ro-show-ip-access-lists-NETOPS-G82-V4__acls.txt").replace("    20 ", "    10 "), "ipv4:NETOPS-G82-V4"),
    ("\nIPv6 access list NETOPS-G82-V6\n", "ipv6:NETOPS-G82-V6"),
], ids=["refused", "another-acl", "standard", "paged", "repeated-number", "ipv6-without-rules"])
def test_check_account_answers_that_are_not_complete_are_unreadable(text, key):
    with pytest.raises(Rejected) as caught:
        observe_acl(text, key)
    assert caught.value.reason_codes == ["ios_acl_readback_unreadable"]


def test_check_account_reads_the_attachment_of_the_measured_interface():
    four, six = (fixture("ro-show-%s-interface-Ethernet0-2__%s.txt" % (family, state)) for family in ("ip", "ipv6")
                 for state in ("bound",))
    plain = {family: fixture("ro-show-%s-interface-Ethernet0-2__acls.txt" % family) for family in ("ip", "ipv6")}
    assert observe_binding(four, IN4) == {"acl": "NETOPS-G82-V4"}
    assert observe_binding(four, OUT4) == {"acl": "NETOPS-G82-V4B"}
    assert observe_binding(six, IN6) == {"acl": "NETOPS-G82-V6"}
    assert observe_binding(six, OUT6) == {"acl": "NETOPS-G82-V6"}
    assert observe_binding(plain["ip"], IN4) == {} == observe_binding(plain["ipv6"], OUT6)
    assert observe_binding("", IN6) == {}  # IPv6 is not enabled on the interface: an empty answer
    for text, key in ((four.split("\n", 4)[-1], IN4), ("", IN4), (four.replace("Ethernet0/2 is", "Ethernet0/3 is"), IN4),
                      ('Line has invalid autocommand "show ip interface"', IN4),
                      (six.replace("Inbound access list NETOPS-G82-V6", "Inbound access list a b"), IN6)):
        with pytest.raises(Rejected) as caught:
            observe_binding(text, key)
        assert caught.value.reason_codes == ["ios_acl_readback_unreadable"]


def test_the_device_refusals_of_acl_lines_are_errors():
    for name, text in (("config__v4-duplicate-sequence.txt", "% Duplicate sequence number"),
                       ("config__v4-duplicate-entry.txt", "% Duplicate entry exists at sequence 30"),
                       ("config__v6-duplicate-entry.txt", "% Duplicate entry exists at sequence 30"),
                       ("config__v4-no-binding-wrong-name.txt", "% Access-group WRONGNAME is not configured"),
                       ("config__v6-no-binding-wrong-name.txt", "% No matching traffic-filter")):
        assert ios.cli_error("x\n" + answer(name)) == text, name
    assert ios.cli_error("x\n" + answer("config__v6-number-without-sequence.txt")).startswith("% Invalid input")
    for name in ("config__v4-ok.txt", "config__v6-ok.txt", "config__binding-ok.txt", "config__v4-acl-enter.txt"):
        assert ios.cli_error("x\n" + answer(name)) is None, name


# ---- plans of ACL rules ----

def test_create_an_ipv4_acl_renders_the_measured_lines_and_the_inverse_deletes_it():
    p = plan(acl("ipv4:NETOPS-G82-NEW", "create", {
        "rules": "20 permit udp any any eq domain, 10 permit tcp 203.0.113.32/27 host 203.0.113.39 eq 22, 30 deny ip any any"}),
        BASELINE)
    assert p["commands"] == ["configure terminal", "ip access-list extended NETOPS-G82-NEW",
                             "10 permit tcp 203.0.113.32 0.0.0.31 host 203.0.113.39 eq 22", "20 permit udp any any eq 53",
                             "30 deny ip any any", "exit", "end"]
    assert p["inverse"] == ["configure terminal", "no ip access-list extended NETOPS-G82-NEW", "end"]
    assert p["predicted"] == {"before": None, "after": {
        "rules": "10 permit tcp 203.0.113.32/27 host 203.0.113.39 eq 22, 20 permit udp any any eq 53, 30 deny ip any any"}}


def test_create_an_ipv6_acl_uses_the_sequence_word_and_the_inverse_deletes_it():
    p = plan(acl("ipv6:NETOPS-G82-NEW6", "create", {
        "rules": "10 permit tcp 2001:DB8:69::/64 any eq 22, 20 deny ipv6 ::/0 ::/0"}), BASELINE)
    assert p["commands"] == ["configure terminal", "ipv6 access-list NETOPS-G82-NEW6",
                             "sequence 10 permit tcp 2001:db8:69::/64 any eq 22", "sequence 20 deny ipv6 any any",
                             "exit", "end"]
    assert p["inverse"] == ["configure terminal", "no ipv6 access-list NETOPS-G82-NEW6", "end"]


def test_an_ipv4_acl_without_rules_is_created_and_an_ipv6_one_is_not():
    empty = plan(acl("ipv4:NETOPS-G82-NEW", "create"), BASELINE)
    assert empty["commands"] == ["configure terminal", "ip access-list extended NETOPS-G82-NEW", "exit", "end"]
    assert empty["predicted"]["after"] == {}
    with pytest.raises(Rejected, match="does not exist on IOS") as caught:
        plan(acl("ipv6:NETOPS-G82-NEW6", "create"), BASELINE)
    assert caught.value.reason_codes == ["ios_acl_unsupported"]
    with pytest.raises(Rejected, match="does not exist on IOS"):
        plan(acl("ipv6:NETOPS-G82-V6", changes={"rules": None}))


def test_changing_a_rule_removes_and_adds_it_again_in_the_order_of_the_numbers():
    changed = V4_RULES.replace("20 permit udp any any eq 53", "20 deny udp any any eq 53").replace(
        "30 permit icmp any any", "15 permit tcp any any eq 8081, 30 permit icmp any any").replace(", 190 permit udp any any eq 67", "")
    p = plan(acl("ipv4:NETOPS-G82-V4", changes={"rules": changed}))
    assert p["commands"] == ["configure terminal", "ip access-list extended NETOPS-G82-V4", "no 20", "no 190",
                             "15 permit tcp any any eq 8081", "20 deny udp any any eq 53", "exit", "end"]
    assert p["inverse"] == ["configure terminal", "ip access-list extended NETOPS-G82-V4", "no 15", "no 20",
                            "20 permit udp any any eq 53", "190 permit udp any any eq 67", "exit", "end"]
    six = plan(acl("ipv6:NETOPS-G82-V6", changes={"rules": V6_RULES.replace(
        "40 deny ipv6 host 2001:db8:69::9 any, ", "45 permit tcp any any eq 443, ")}))
    assert six["commands"] == ["configure terminal", "ipv6 access-list NETOPS-G82-V6", "no sequence 40",
                               "sequence 45 permit tcp any any eq 443", "exit", "end"]
    assert six["inverse"] == ["configure terminal", "ipv6 access-list NETOPS-G82-V6", "no sequence 45",
                              "sequence 40 deny ipv6 host 2001:db8:69::9 any", "exit", "end"]


def test_emptying_an_ipv4_acl_removes_every_rule_and_keeps_the_acl():
    p = plan(acl("ipv4:NETOPS-G82-V4", changes={"rules": None}))
    assert p["commands"][:2] == ["configure terminal", "ip access-list extended NETOPS-G82-V4"]
    assert p["commands"][2:-2] == ["no %d" % seq for seq in (10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130,
                                                              140, 150, 160, 170, 180, 190)]
    assert p["predicted"]["after"] == {}


def test_deleting_an_acl_and_its_inverse_with_the_numbers():
    p = plan(acl("ipv6:NETOPS-G82-V6", "delete"))
    assert p["commands"] == ["configure terminal", "no ipv6 access-list NETOPS-G82-V6", "end"]
    assert p["inverse"][:3] == ["configure terminal", "ipv6 access-list NETOPS-G82-V6",
                                "sequence 10 permit tcp 2001:db8:69::/64 host 2001:db8:69::7 eq 22"]
    assert p["inverse"][-3:] == ["sequence 100 permit ipv6 any 2001:db8:69::/64", "exit", "end"]
    gone = plan(acl("ipv4:NETOPS-G82-V4C", "delete"))
    assert gone["inverse"] == ["configure terminal", "ip access-list extended NETOPS-G82-V4C", "exit", "end"]


@pytest.mark.parametrize("rules,message", [
    ("10 permit tcp 203.0.113.32/27", "need a sequence|ACL rule 10|must be distinct"),
    ("permit tcp any any", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit gre any any", "need a sequence|ACL rule 10|must be distinct"),
    ("10 allow ip any any", "need a sequence|ACL rule 10|must be distinct"),
    ("0 permit ip any any", "need a sequence|ACL rule 10|must be distinct"),
    ("2147483648 permit ip any any", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit icmp any any eq 5", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit tcp any any eq nosuchport", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit tcp any any eq 65536", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit tcp any eq 22 any", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit ipv6 any any", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit ip 2001:db8::/32 any", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit ip 203.0.113.33/27 any", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit ip 203.0.113.32 0.0.0.31 any", "need a sequence|ACL rule 10|must be distinct"),
    ("10 permit ip any any, 10 deny ip any any", "distinct"),
    ("10 permit ip any any, 20 permit ip any any", "same body"),
    ("10 permit ip any any 20 permit ip any any", "need a sequence|ACL rule 10|must be distinct"),
], ids=lambda value: value[:30])
def test_unusable_rules_are_refused_before_any_write(rules, message):
    with pytest.raises(Rejected, match=message) as caught:
        plan(acl("ipv4:NETOPS-G82-NEW", "create", {"rules": rules}), BASELINE)
    assert caught.value.reason_codes == ["ios_acl_unsupported"]


def test_ipv6_rules_are_checked_with_the_family_of_the_key():
    for rules in ("10 permit ip any any", "10 permit tcp 203.0.113.32/27 any", "4294967295 permit ipv6 any any",
                  "10 permit icmpv6 any any"):
        with pytest.raises(Rejected, match="need a sequence|ACL rule 10|must be distinct"):
            plan(acl("ipv6:NETOPS-G82-NEW6", "create", {"rules": rules}), BASELINE)
    plan(acl("ipv6:NETOPS-G82-NEW6", "create", {"rules": "4294967294 permit ipv6 any any"}), BASELINE)


def test_an_acl_outside_the_profile_or_unknown_is_not_changed():
    with pytest.raises(Rejected, match="outside the profile"):
        plan(acl("ipv4:NETOPS-G82-V4B", changes={"rules": "10 permit ip any any"}), ACLS)
    with pytest.raises(Rejected, match="outside the profile"):
        plan(acl("ipv6:NETOPS-G82-V6", "delete"), ACLS)
    with pytest.raises(Rejected, match="not in the running configuration"):
        plan(acl("ipv4:NETOPS-G82-NEW", changes={"rules": "10 permit ip any any"}), ACLS_OK)
    with pytest.raises(Rejected, match="already used"):
        plan(acl("ipv4:NETOPS-G82-V4", "create", {"rules": "10 permit ip any any"}))
    with pytest.raises(Rejected, match="update changes nothing"):
        plan(acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES}))
    with pytest.raises(Rejected, match="does not match"):
        plan(acl("NETOPS-G82-V4", "create", {"rules": "10 permit ip any any"}))


def test_an_acl_used_by_something_else_than_an_interface_is_not_changed():
    # G69-PBR-ACL is the real ACL of a route-map of the lab router
    with pytest.raises(Rejected) as caught:
        plan(acl("ipv4:G69-PBR-ACL", changes={"rules": "10 permit ip any 203.0.113.96/28"}), ACLS_OK)
    assert caught.value.reason_codes == ["ios_acl_in_use"]
    used = ACLS_OK.replace("control-plane\n", "ntp access-group peer NETOPS-G82-V4C\ncontrol-plane\n", 1)
    assert "ntp access-group peer NETOPS-G82-V4C" in used
    with pytest.raises(Rejected) as caught:
        plan(acl("ipv4:NETOPS-G82-V4C", "delete"), used)
    assert caught.value.reason_codes == ["ios_acl_in_use"]


def test_an_attached_acl_keeps_its_rules_and_its_interface_is_checked():
    with pytest.raises(Rejected) as caught:
        plan(acl("ipv4:NETOPS-G82-V4", "delete"), BOUND_OK)
    assert caught.value.reason_codes == ["ios_acl_in_use"]
    with pytest.raises(Rejected) as caught:
        plan(acl("ipv4:NETOPS-G82-V4", changes={"rules": None}), BOUND_OK)
    assert caught.value.reason_codes == ["ios_acl_in_use"]
    changed = V4_RULES.replace("20 permit udp any any eq 53", "20 deny udp any any eq 53")
    p = plan(acl("ipv4:NETOPS-G82-V4", changes={"rules": changed}), BOUND_OK)
    assert p["commands"][2:4] == ["no 20", "20 deny udp any any eq 53"]
    for guarded, code in (({"interface": ["ethernet0/2"]}, "port_protected"),
                          ({"ip-access-list": ["IPV4:netops-g82-v4"]}, "ios_acl_in_use"),
                          ({"ip-access-list": ["NETOPS-G82-V4"]}, "ios_acl_in_use"),
                          ({"interface-access-group": ["ethernet0/2:IPV4:in"]}, "port_protected")):
        with pytest.raises(Rejected) as caught:
            plan(acl("ipv4:NETOPS-G82-V4", changes={"rules": changed}), BOUND_OK, protected=guarded)
        assert caught.value.reason_codes == [code], guarded


# ---- plans of attachments ----

def test_attach_replace_and_remove_render_the_measured_lines():
    attach = plan(bind("Ethernet0/2:ipv4:in", "NETOPS-G82-V4"))
    assert attach["commands"] == ["configure terminal", "interface Ethernet0/2", "ip access-group NETOPS-G82-V4 in",
                                  "end"]
    assert attach["inverse"] == ["configure terminal", "interface Ethernet0/2", "no ip access-group NETOPS-G82-V4 in",
                                 "end"]
    assert attach["predicted"] == {"before": {}, "after": {"acl": "NETOPS-G82-V4"}}
    # the device replaces the ACL of the same direction: one line, no gap without a filter
    swap = plan(bind(IN4, "NETOPS-G82-V4C"), BOUND_OK.replace(
        "ip access-list extended NETOPS-G82-V4C\n", "ip access-list extended NETOPS-G82-V4C\n 10 permit ip any any\n"))
    assert swap["commands"] == ["configure terminal", "interface Ethernet0/2", "ip access-group NETOPS-G82-V4C in",
                                "end"]
    assert swap["inverse"] == ["configure terminal", "interface Ethernet0/2", "ip access-group NETOPS-G82-V4 in", "end"]
    remove = plan(bind(OUT4, None), BOUND_OK)
    assert remove["commands"] == ["configure terminal", "interface Ethernet0/2", "no ip access-group NETOPS-G82-V4B out",
                                  "end"]
    assert remove["inverse"] == ["configure terminal", "interface Ethernet0/2", "ip access-group NETOPS-G82-V4B out",
                                 "end"]
    six = plan(bind(IN6, "NETOPS-G82-V6"))
    assert six["commands"][2] == "ipv6 traffic-filter NETOPS-G82-V6 in"
    assert plan(bind(OUT6, None), BOUND_OK)["commands"][2] == "no ipv6 traffic-filter NETOPS-G82-V6 out"


@pytest.mark.parametrize("key,name,text,code", [
    (IN4, "NETOPS-G82-NOPE", ACLS_OK, "ios_acl_undefined"),
    (IN4, "NETOPS-G82-V4C", ACLS_OK, "ios_acl_undefined"),            # exists without rules: not bindable
    (IN4, "NETOPS-G82-V4B", ACLS, "ios_acl_undefined"),               # outside the profile
    (IN4, "NETOPS-G82-V6", ACLS_OK, "ios_acl_undefined"),             # the ACL of the other family
    (IN6, "NETOPS-G82-V4", ACLS_OK, "ios_acl_undefined"),
    ("Ethernet0/3:ipv4:in", "NETOPS-G82-V4", ACLS_OK, "ios_acl_unsupported"),   # no IPv4 address on the port
    ("Ethernet0/3:ipv6:in", "NETOPS-G82-V6", ACLS_OK, "ios_acl_unsupported"),
], ids=["missing", "empty", "outside-profile", "other-family", "other-family-6", "no-ipv4", "no-ipv6"])
def test_an_attachment_needs_an_existing_nonempty_acl_and_an_address_of_the_family(key, name, text, code):
    with pytest.raises(Rejected) as caught:
        plan(bind(key, name), text)
    assert caught.value.reason_codes == [code]


def test_an_attachment_of_a_missing_acl_can_be_removed_but_not_made():
    # the device accepts `ip access-group` with an ACL that does not exist (measured); such an attachment is removable
    dangling = ACLS_OK.replace("interface Ethernet0/3\n no ip address\n shutdown\n",
                               "interface Ethernet0/3\n ip address 192.0.2.30 255.255.255.0\n ip access-group NETOPS-G82-GONE in\n"
                               " shutdown\n")
    assert "NETOPS-G82-GONE" in dangling
    remove = plan(bind("Ethernet0/3:ipv4:in", None), dangling)
    assert remove["commands"] == ["configure terminal", "interface Ethernet0/3", "no ip access-group NETOPS-G82-GONE in",
                                  "end"]
    with pytest.raises(Rejected) as caught:
        plan(bind("Ethernet0/3:ipv4:out", "NETOPS-G82-GONE"), dangling)
    assert caught.value.reason_codes == ["ios_acl_undefined"]


def test_an_unchanged_or_absent_attachment_is_refused():
    with pytest.raises(Rejected, match="update changes nothing"):
        plan(bind(IN4, "NETOPS-G82-V4"), BOUND_OK)
    with pytest.raises(Rejected, match="update changes nothing"):
        plan(bind(IN4, None), ACLS_OK)
    with pytest.raises(Rejected, match="not a supported interface of the running configuration"):
        plan(bind("Ethernet9/9:ipv4:in", "NETOPS-G82-V4"))
    for key in ("Loopback0:ipv4:in", "Ethernet0/2:ipv4:both", "Ethernet0/2:ipx:in"):
        with pytest.raises(Rejected, match="does not match"):
            plan(bind(key, "NETOPS-G82-V4"))
    with pytest.raises(Rejected, match="must match"):
        plan(bind(IN4, "1bad name"))


def with_interface(text, block):
    return text.replace("interface Ethernet0/3\n", block + "interface Ethernet0/3\n", 1)


@pytest.mark.parametrize("block,key,code", [
    ("interface Vlan10\n ip address 192.0.2.10 255.255.255.0\n!\n", "Vlan10:ipv4:in", "port_protected"),
    ("interface Port-channel5\n ip address 192.0.2.10 255.255.255.0\n!\n", "Port-channel5:ipv4:in", "port_protected"),
    ("interface Ethernet0/2.80\n encapsulation dot1Q 80\n ip address 192.0.2.10 255.255.255.0\n!\n",
     "Ethernet0/2.80:ipv4:in", "port_protected"),
], ids=["svi", "port-channel", "subinterface-of-protected-port"])
def test_protected_interface_applies_to_every_interface_type(block, key, code):
    name = key.split(":")[0]
    text = with_interface(ACLS_OK, block)
    plan(bind(key, "NETOPS-G82-V4"), text)  # allowed when nothing is protected
    guarded = {"interface": [name.casefold() if "." not in name else "ETHERNET0/2"]}
    with pytest.raises(Rejected) as caught:
        plan(bind(key, "NETOPS-G82-V4"), text, protected=guarded)
    assert caught.value.reason_codes == [code]


@pytest.mark.parametrize("block,key,code", [
    ("interface Ethernet0/3\n vrf forwarding Mgmt-vrf\n ip address 192.0.2.10 255.255.255.0\n", "Ethernet0/3:ipv4:in",
     "port_management_interface"),
    ("interface Ethernet0/3\n channel-group 5 mode active\n ip address 192.0.2.10 255.255.255.0\n", "Ethernet0/3:ipv4:in",
     "port_lag_member"),
    ("interface Ethernet0/3\n switchport mode access\n ip address 192.0.2.10 255.255.255.0\n", "Ethernet0/3:ipv4:in",
     "port_unsupported_interface"),
    ("interface Ethernet0/3\n switchport\n ip address 192.0.2.10 255.255.255.0\n", "Ethernet0/3:ipv4:in",
     "port_unsupported_interface"),
], ids=["management-vrf", "port-channel-member", "access-port", "switchport"])
def test_interfaces_that_cannot_carry_the_acl_are_refused(block, key, code):
    text = ACLS_OK.replace("interface Ethernet0/3\n no ip address\n shutdown\n", block + " shutdown\n")
    assert block in text
    with pytest.raises(Rejected) as caught:
        plan(bind(key, "NETOPS-G82-V4"), text)
    assert caught.value.reason_codes == [code]


def test_an_acl_attached_to_a_management_vrf_interface_is_refused():
    text = BOUND_OK.replace("interface Ethernet0/2\n description port-desc-01\n vrf forwarding blue\n",
                            "interface Ethernet0/2\n description port-desc-01\n vrf forwarding Mgmt-vrf\n")
    with pytest.raises(Rejected) as caught:
        plan(acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES.replace("eq 53", "eq 54")}), text)
    assert caught.value.reason_codes == ["port_management_interface"]


# ---- bod 20: the hash, the impact, the plan binding ----

def test_endpoint_impact_is_accepted_by_the_planner_for_both_tables():
    changed = V4_RULES.replace("20 permit udp any any eq 53", "20 deny udp any any eq 53")
    for req in (acl("ipv4:NETOPS-G82-V4", changes={"rules": changed}, endpoint_impact="ipv4:NETOPS-G82-V4"),
                bind(IN4, "NETOPS-G82-V4", endpoint_impact=IN4)):
        text = BOUND_OK if req.table == ios_acl.ACL else ACLS_OK
        p = plan(req, text)
        assert p["endpoint_impact"] == req.key
        assert any("endpoint impact accepted" in check for check in p["prechecks"])
        engine._read_plan(p)  # the journalled plan keeps its endpoint_impact only when it names the key


def test_the_plan_hash_binds_the_rest_of_the_configuration():
    base = plan(bind(IN4, "NETOPS-G82-V4"))
    again = plan(bind(IN4, "NETOPS-G82-V4"))
    assert base["plan_sha256"] == again["plan_sha256"]
    # the content of the ACL changes between the approval and the apply: the approved hash no longer matches
    other = ACLS_OK.replace(" 20 permit udp any any eq domain\n", " 20 deny udp any any eq domain\n")
    assert plan(bind(IN4, "NETOPS-G82-V4"), other)["plan_sha256"] != base["plan_sha256"]
    assert base["rest_sha256"] == active(ACLS_OK).rest_digest(ios_acl.BINDING, IN4)


def test_rest_digest_ignores_the_own_object_the_volatile_header_and_separators():
    p = plan(acl("ipv4:NETOPS-G82-V4C", changes={"rules": "10 permit ip any any"}))
    after = ACLS_OK.replace("ip access-list extended NETOPS-G82-V4C\n", "ip access-list extended NETOPS-G82-V4C\n"
                            " 10 permit ip any any\n").replace("! Last configuration change at", "! Last configuration change at 00:00 x")
    assert engine.verify(p, after.encode())["result"] == "match"
    foreign = after.replace(" 20 permit udp any any eq domain\n", " 20 deny udp any any eq domain\n")
    result = engine.verify(p, foreign.encode())
    assert result["result"] == "mismatch" and result["rest_matches"] is False
    # a changed attachment of another interface direction is a change outside the object
    bound = engine.verify(plan(bind(IN4, "NETOPS-G82-V4")), BOUND_OK.replace(
        " ip access-group NETOPS-G82-V4B out\n", "").encode())
    assert bound["object_matches"] is True and bound["rest_matches"] is False


# ---- live prechecks of Admin (write account reads) ----

def test_a_definition_that_is_not_attached_needs_no_live_read():
    device = G82Ios(ACLS_OK)
    p = plan(acl("ipv4:NETOPS-G82-NEW", "create", {"rules": "10 permit ip any any"}))
    assert exec_ios.plan_prechecks(device, DEVICE, p, ACLS_OK) == []
    assert device.queries == [] and any("not attached" in check for check in p["prechecks"])


def test_an_up_interface_needs_endpoint_impact_naming_the_key():
    for req, text in ((bind(IN4, "NETOPS-G82-V4"), ACLS_OK),
                      (acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES.replace("eq 53", "eq 54")}), BOUND_OK)):
        device = G82Ios(text)
        p = plan(req, text)
        with pytest.raises(Rejected) as caught:
            exec_ios.plan_prechecks(device, DEVICE, p, text)
        assert caught.value.reason_codes == ["endpoint_impact_required"]
        impact = plan(parse_request(request_bytes(table=req.table, op="update", key=req.key, changes=req.changes,
                                                  request_id="req-g82-0002", endpoint_impact=req.key)), text)
        assert exec_ios.plan_prechecks(device, DEVICE, impact, text) == []
        assert any("Ethernet0/2 is up/up" in check for check in impact["prechecks"])
        other = dict(impact, endpoint_impact="Ethernet0/3:ipv4:in")  # an impact that names another object
        with pytest.raises(Rejected) as caught:
            exec_ios.plan_prechecks(device, DEVICE, other, text)
        assert caught.value.reason_codes == ["endpoint_impact_required"]


def test_a_down_interface_needs_no_impact():
    device = G82Ios(ACLS_OK)
    device.down.add("Et0/2")
    p = plan(bind(IN4, "NETOPS-G82-V4"))
    assert exec_ios.plan_prechecks(device, DEVICE, p, ACLS_OK) == []
    assert any("Ethernet0/2 is admin down/down" in check for check in p["prechecks"])


def test_the_management_interface_is_refused_whatever_the_impact():
    # Ethernet0/0 carries the SSH session of the measured device (show tcp brief, show ip interface brief)
    req = bind("Ethernet0/0:ipv4:in", "NETOPS-G82-V4", endpoint_impact="Ethernet0/0:ipv4:in")
    device = G82Ios(ACLS_OK)
    p = plan(req, ACLS_OK)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, ACLS_OK)
    assert caught.value.reason_codes == ["port_management_interface"]
    attached = BOUND_OK.replace(" ip access-group NETOPS-G82-V4 in\n", "").replace(
        "interface Ethernet0/0\n", "interface Ethernet0/0\n ip access-group NETOPS-G82-V4 in\n", 1)
    device = G82Ios(attached)
    p = plan(acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES.replace("eq 53", "eq 54")},
                 endpoint_impact="ipv4:NETOPS-G82-V4"), attached)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, attached)
    assert caught.value.reason_codes == ["port_management_interface"]


def test_a_management_vlan_svi_and_a_protected_vlan_are_refused():
    svi = with_interface(ACLS_OK, "interface Vlan99\n ip address 192.0.2.57 255.255.255.0\n!\n")
    device = G82Ios(svi)
    device.query_override["show tcp brief"] = fixture("admin-show-tcp-brief.txt")
    device.query_override["show ip interface brief"] = fixture("admin-show-ip-interface-brief.txt").replace(
        "Ethernet0/0            192.0.2.57  ", "Vlan99                 192.0.2.57  ")
    p = plan(bind("Vlan99:ipv4:in", "NETOPS-G82-V4"), svi)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, svi)
    assert caught.value.reason_codes == ["port_management_vlan"]
    other = with_interface(ACLS_OK, "interface Vlan10\n ip address 192.0.2.10 255.255.255.0\n!\n")
    p = plan(bind("Vlan10:ipv4:in", "NETOPS-G82-V4"), other)
    guarded = type("Device", (), {"platform": "iosxe", "firmware": FW, "protected": {"vlan": ["10"]}})()
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(G82Ios(other), guarded, p, other)
    assert caught.value.reason_codes == ["port_management_vlan"]


def test_a_layer_2_port_is_detected_by_the_device_not_by_the_image_name():
    device = G82Ios(ACLS_OK)
    # a switch image answers show interfaces <port> switchport; the measured L2 answer of IOL-L2 XE 17.18.2 (G81)
    layer2 = (Path(__file__).parent / "fixtures" / "ios_g81" / "ro-show-interfaces-Ethernet0-1-switchport__baseline.txt"
              ).read_text().replace("Et0/1", "Et0/2")
    device.query_override["show interfaces Ethernet0/2 switchport"] = layer2
    p = plan(bind(IN4, "NETOPS-G82-V4", endpoint_impact=IN4))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, ACLS_OK)
    assert caught.value.reason_codes == ["port_unsupported_interface"]
    routed = layer2.replace("Switchport: Enabled", "Switchport: Disabled")
    device.query_override["show interfaces Ethernet0/2 switchport"] = routed
    assert exec_ios.plan_prechecks(device, DEVICE, p, ACLS_OK) == []
    device.query_override["show interfaces Ethernet0/2 switchport"] = "Name: Et0/2\nSwitchport: Enabled\n"
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, ACLS_OK)
    assert caught.value.reason_codes == ["ios_acl_readback_unreadable"]


@pytest.mark.parametrize("break_it,code", [
    (lambda device: device.query_override.update({"show interfaces description": "\n\nLine has invalid autocommand"}),
     "ios_acl_readback_unreadable"),
    (lambda device: device.query_override.update({"show interfaces description": "Interface Status Protocol Description\n"}),
     "ios_acl_readback_unreadable"),
    (lambda device: device.query_override.update({"show tcp brief": ""}), "port_usage_unreadable"),
], ids=["refused", "empty-table", "no-management-session"])
def test_a_failed_preflight_read_has_its_own_reason_code(break_it, code):
    device = G82Ios(ACLS_OK)
    break_it(device)
    p = plan(bind(IN4, "NETOPS-G82-V4", endpoint_impact=IN4))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, ACLS_OK)
    assert caught.value.reason_codes == [code]


@pytest.mark.parametrize("message,code", [("read timeout after 20 s", "ios_acl_read_timeout"),
                                          ("connection reset", "ios_acl_readback_unreadable")])
def test_a_timeout_is_not_a_refusal(message, code):
    device = G82Ios(ACLS_OK)

    def broken(command):
        raise AccessError(message)

    original = device.query

    def query(command):
        if command == "show interfaces description":
            broken(command)
        return original(command)

    device.query = query
    p = plan(bind(IN4, "NETOPS-G82-V4", endpoint_impact=IN4))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, DEVICE, p, ACLS_OK)
    assert caught.value.reason_codes == [code]


def test_observe_reads_the_object_with_the_check_account():
    device = G82Ios(BOUND_OK)
    p = plan(acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES.replace("eq 53", "eq 54")}), BOUND_OK)
    assert engine.observed_state(p, exec_ios.observe(device, p)) == p["predicted"]["before"]
    q = plan(bind(OUT4, None), BOUND_OK)
    assert engine.observed_state(q, exec_ios.observe(device, q)) == q["predicted"]["before"] == {"acl": "NETOPS-G82-V4B"}
    assert device.check_queries == ["show ip access-lists NETOPS-G82-V4", "show ip interface Ethernet0/2"]
    new = plan(acl("ipv6:NETOPS-G82-NEW6", "create", {"rules": "10 permit ipv6 any any"}), BASELINE)
    assert exec_ios.observe(G82Ios(BASELINE), new) is None
    empty = plan(acl("ipv4:NETOPS-G82-V4C", changes={"rules": "10 permit ip any any"}))
    assert exec_ios.observe(G82Ios(ACLS_OK), empty) == {}


# ---- end to end through Admin: preview without a write, hash, apply, readback, undo ----

def test_preview_writes_nothing_and_apply_without_the_approved_hash_is_refused(tmp_path):
    device = G82Ios(BASELINE)
    rt = runtime(tmp_path, device)
    req = acl("ipv4:NETOPS-G82-NEW", "create", {"rules": "10 permit ip any any"})
    result = execute.preview(rt, "lab-ios", req)
    assert result["result"] == "ready", result
    assert device.applied_blocks == [] and device.lines == device.saved
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab-ios", req)
    assert caught.value.reason_codes == ["plan_changed"] and device.applied_blocks == []
    attach = bind(IN4, "NETOPS-G82-V4", request_id="req-g82-0009")
    (tmp_path / "b").mkdir()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime(tmp_path / "b", G82Ios(ACLS_OK)), "lab-ios", attach)
    assert caught.value.reason_codes == ["plan_changed"]
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab-ios", req, expected_plan_sha256="0" * 64)
    assert caught.value.reason_codes == ["plan_changed"] and device.applied_blocks == []


def test_a_changed_acl_between_preview_and_apply_is_refused(tmp_path):
    device = G82Ios(ACLS_OK)
    rt = runtime(tmp_path, device)
    req = bind(IN4, "NETOPS-G82-V4", endpoint_impact=IN4)
    expected = approved(rt, req)
    start, end = device._block("ip access-list extended NETOPS-G82-V4")
    device.lines[start + 2] = " 20 deny udp any any eq domain"
    device.saved = list(device.lines)  # a saved change of someone else, not an unsaved one
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab-ios", req, expected_plan_sha256=expected)
    assert caught.value.reason_codes == ["plan_changed"] and device.applied_blocks == []


def test_create_ipv4_and_ipv6_acls_are_read_back_and_undone_to_the_baseline(tmp_path):
    device = G82Ios(BASELINE)
    rt = runtime(tmp_path, device)
    before = stable(device.lines)
    four = apply(rt, acl("ipv4:NETOPS-G82-NEW", "create", {
        "rules": "10 permit tcp 203.0.113.32/27 host 203.0.113.39 eq 22, 20 permit udp any any eq 53, 30 deny ip any any"}))
    assert four["result"] == "confirmed", (four["reason"], steps(four))
    assert device.applied_blocks[1] == four["plan"]["commands"] and device.timer is None
    assert " 20 permit udp any any eq domain" in device.lines
    six = apply(rt, acl("ipv6:NETOPS-G82-NEW6", "create", {"rules": "5 permit tcp 2001:DB8:69::/64 any eq 22, "
                                                                    "9 deny ipv6 any any"}, request_id="req-g82-0002"))
    assert six["result"] == "confirmed", (six["reason"], steps(six))
    assert " sequence 5 permit tcp 2001:DB8:69::/64 any eq 22" in device.lines
    assert "show ipv6 access-list NETOPS-G82-NEW6" in device.check_queries
    for record in (six, four):
        back = execute.undo(rt, record["change_id"], "G82 return")
        assert back["result"] == "confirmed", (back["reason"], steps(back))
    assert stable(device.lines) == before and device.timer is None


def test_change_of_a_rule_keeps_the_numbers_and_is_undone_exactly(tmp_path):
    device = G82Ios(ACLS_OK)
    rt = runtime(tmp_path, device)
    before = stable(device.lines)
    changed = V4_RULES.replace("20 permit udp any any eq 53", "20 deny udp any any eq 53").replace(
        "30 permit icmp any any", "25 permit tcp any any eq 8081, 30 permit icmp any any")
    record = apply(rt, acl("ipv4:NETOPS-G82-V4", changes={"rules": changed}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    block = device._rules("ip access-list extended NETOPS-G82-V4")[2]
    assert block[:3] == ["10 permit tcp 203.0.113.32 0.0.0.31 host 203.0.113.39 eq 22", "20 deny udp any any eq domain",
                         "25 permit tcp any any eq 8081"]
    back = execute.undo(rt, record["change_id"], "G82 return")
    assert back["result"] == "confirmed", (back["reason"], steps(back))
    assert stable(device.lines) == before
    six = apply(rt, acl("ipv6:NETOPS-G82-V6", changes={"rules": V6_RULES.replace("60 permit tcp any any eq 80, ", "")},
                        request_id="req-g82-0004"))
    assert six["result"] == "confirmed", (six["reason"], steps(six))
    assert not any("sequence 60 " in line for line in device.lines)
    back = execute.undo(rt, six["change_id"], "G82 return")
    assert back["result"] == "confirmed" and stable(device.lines) == before


def test_delete_acl_and_undo_restore_the_numbers_and_the_empty_acl(tmp_path):
    for key, text in (("ipv4:NETOPS-G82-V4", ACLS_OK), ("ipv6:NETOPS-G82-V6", ACLS_OK), ("ipv4:NETOPS-G82-V4C", ACLS_OK)):
        device = G82Ios(text)
        (tmp_path / key.replace(":", "_")).mkdir()
        rt = runtime(tmp_path / key.replace(":", "_"), device)
        before = stable(device.lines)
        record = apply(rt, acl(key, "delete"))
        assert record["result"] == "confirmed", (key, record["reason"], steps(record))
        assert not any(line.endswith(key.split(":")[1]) for line in device.lines)
        back = execute.undo(rt, record["change_id"], "G82 return")
        assert back["result"] == "confirmed", (key, back["reason"], steps(back))
        assert stable(device.lines) == before, key


def test_attachments_need_the_impact_on_the_up_interface_and_are_undone(tmp_path):
    device = G82Ios(ACLS_OK)
    rt = runtime(tmp_path, device)
    before = stable(device.lines)
    refused = execute.preview(rt, "lab-ios", bind(IN4, "NETOPS-G82-V4"))
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["endpoint_impact_required"], refused
    assert device.applied_blocks == []
    records = []
    for number, (key, acl_name) in enumerate(((IN4, "NETOPS-G82-V4"), (OUT4, "NETOPS-G82-V4"), (IN6, "NETOPS-G82-V6"),
                                              (OUT6, "NETOPS-G82-V6"))):
        record = apply(rt, bind(key, acl_name, endpoint_impact=key, request_id="req-g82-b%03d" % number))
        assert record["result"] == "confirmed", (key, record["reason"], steps(record))
        assert record["plan"]["endpoint_impact"] == key
        records.append(record)
    assert [line for line in device.interface(PORT) if "access" in line or "traffic" in line] == [
        "ip access-group NETOPS-G82-V4 in", "ip access-group NETOPS-G82-V4 out", "ipv6 traffic-filter NETOPS-G82-V6 in",
        "ipv6 traffic-filter NETOPS-G82-V6 out"]
    assert "show ip interface Ethernet0/2" in device.check_queries and "show ipv6 interface Ethernet0/2" in device.check_queries
    for number, record in enumerate(reversed(records)):
        back = execute.undo(rt, record["change_id"], "G82 return")
        assert back["result"] == "confirmed", (number, back["reason"], steps(back))
    assert stable(device.lines) == before


def test_replace_and_remove_of_an_attachment_and_the_change_of_an_attached_acl(tmp_path):
    swap_text = BOUND_OK.replace("ip access-list extended NETOPS-G82-V4C\n", "ip access-list extended NETOPS-G82-V4C\n"
                                 " 10 permit ip any any\n")
    device = G82Ios(swap_text)
    rt = runtime(tmp_path / "swap", device)
    before = stable(device.lines)
    swapped = apply(rt, bind(IN4, "NETOPS-G82-V4C", endpoint_impact=IN4))
    assert swapped["result"] == "confirmed", (swapped["reason"], steps(swapped))
    assert device._bound(PORT, "ip access-group", "in") == "NETOPS-G82-V4C"
    removed = apply(rt, bind(OUT4, None, endpoint_impact=OUT4, request_id="req-g82-0006"))
    assert removed["result"] == "confirmed", (removed["reason"], steps(removed))
    assert device._bound(PORT, "ip access-group", "out") is None
    changed = apply(rt, acl("ipv6:NETOPS-G82-V6", changes={"rules": V6_RULES.replace("eq 80", "eq 81")},
                            endpoint_impact="ipv6:NETOPS-G82-V6", request_id="req-g82-0007"))
    assert changed["result"] == "confirmed", (changed["reason"], steps(changed))
    for record in (changed, removed, swapped):
        back = execute.undo(rt, record["change_id"], "G82 return")
        assert back["result"] == "confirmed", (back["reason"], steps(back))
    assert stable(device.lines) == before


def test_a_change_of_an_attached_acl_without_the_impact_is_refused_before_any_write(tmp_path):
    device = G82Ios(BOUND_OK)
    rt = runtime(tmp_path, device)
    result = execute.preview(rt, "lab-ios", acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES.replace(
        "eq 53", "eq 54")}))
    assert result["result"] == "rejected" and result["reason_codes"] == ["endpoint_impact_required"]
    assert device.applied_blocks == [] and device.lines == device.saved


def test_a_device_refusal_during_the_write_is_returned_by_the_timer(tmp_path):
    device = G82Ios(ACLS_OK)
    rt = runtime(tmp_path, device)
    before = list(device.lines)

    # someone adds rule 25 right before the write; IOS refuses the same number (measured answer) and the timer returns
    def taken(fake, block):
        if block[:2] == ["configure terminal", "ip access-list extended NETOPS-G82-V4"]:
            start, _ = fake._block("ip access-list extended NETOPS-G82-V4")
            fake.lines[start + 3:start + 3] = [" 25 permit tcp any any eq 8081"]

    device.on_apply = taken
    record = apply(rt, acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES.replace("30 permit icmp any any",
                                                                                   "25 deny tcp any any eq 8082, 30 permit icmp any any")}))
    assert record["result"] in ("reverted", "unknown"), (record["result"], steps(record))
    assert "change_failed" in names(record) and device.lines == before


def test_a_readback_that_differs_from_the_plan_is_returned(tmp_path):
    device = G82Ios(ACLS_OK)
    rt = runtime(tmp_path, device)
    before = list(device.lines)
    original = device._show_acl

    def lying(command, name):
        text = original(command, name)
        return text.replace("eq 8443", "eq 8444") if name == "NETOPS-G82-V4" and len(device.applied_blocks) >= 2 else text

    device._show_acl = lying
    record = apply(rt, acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES.replace("eq 53", "eq 54")}))
    assert record["result"] in ("reverted", "unknown"), (record["result"], steps(record))
    assert device.lines == before


def test_a_foreign_change_during_the_write_is_detected_and_returned(tmp_path):
    device = G82Ios(ACLS_OK)
    rt = runtime(tmp_path, device)
    before = list(device.lines)

    def foreign(fake, block):
        if block[:2] == ["configure terminal", "ip access-list extended NETOPS-G82-V4C"]:
            index = fake.lines.index("interface Ethernet0/3")
            fake.lines[index + 1:index + 1] = [" description someone else"]

    device.on_apply = foreign
    record = apply(rt, acl("ipv4:NETOPS-G82-V4C", changes={"rules": "10 permit ip any any"}))
    assert record["result"] == "reverted" and "postcheck_failed" in names(record), (record["result"], steps(record))
    assert device.lines == before


def test_counters_of_the_rules_do_not_disturb_the_readback(tmp_path):
    device = G82Ios(ACLS_OK)
    device.hits = {("ipv4", "NETOPS-G82-V4", 10): "(5824 matches)", ("ipv4", "NETOPS-G82-V4", 20): "(1 match)"}
    rt = runtime(tmp_path, device)
    record = apply(rt, acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES.replace("eq 53", "eq 54")}))
    assert record["result"] == "confirmed", (record["reason"], steps(record))


def test_the_unsaved_change_of_someone_else_is_not_overwritten(tmp_path):
    device = G82Ios(ACLS_OK)
    device.lines.insert(len(device.lines) - 1, "ip access-list extended NETOPS-G82-FOREIGN")
    rt = runtime(tmp_path, device)
    result = execute.preview(rt, "lab-ios", acl("ipv4:NETOPS-G82-NEW", "create", {"rules": "10 permit ip any any"}))
    assert result["result"] == "rejected" and device.applied_blocks == []


def test_other_firmware_is_only_a_warning():
    tested = plan(acl("ipv4:NETOPS-G82-NEW", "create", {"rules": "10 permit ip any any"}))
    other = engine.build_plan("iosxe", ACLS_OK.replace("version 17.18", "version 17.19").encode(), acl(
        "ipv4:NETOPS-G82-NEW", "create", {"rules": "10 permit ip any any"}), firmware="17.19.1")
    assert other["firmware_support"]["status"] != tested["firmware_support"]["status"]
    assert other["commands"] == tested["commands"]


def test_classic_ios_retains_its_acl_profile():
    planned = engine.build_plan("ios", BASELINE.replace("17.18", "15.9").encode(), acl(
        "ipv4:NETOPS-G82-NEW", "create", {"rules": "10 permit ip any any"}), firmware="15.9(3)M12")
    assert planned["commands"][1:3] == ["ip access-list extended NETOPS-G82-NEW", "10 permit ip any any"]
    assert planned["platform"] == "ios"


@pytest.mark.parametrize("operation", ["attach", "edit-attached"])
def test_loopback_ssh_peer_route_is_protected_even_with_impact(tmp_path, operation):
    text = ACLS_OK if operation == "attach" else BOUND_OK
    device = G82Ios(text)
    device.query_override["show tcp brief"] = fixture("admin-show-tcp-brief.txt").replace(
        "192.0.2.57.22", "203.0.113.253.22")
    route_read = "show ip cef 203.0.113.66 detail"
    device.query_override[route_read] = fixture("admin-show-ip-cef-default-detail.txt").replace("Ethernet0/0", PORT)
    rt = runtime(tmp_path, device)
    wanted = (bind(IN4, "NETOPS-G82-V4", endpoint_impact=IN4) if operation == "attach" else
              acl("ipv4:NETOPS-G82-V4", changes={"rules": V4_RULES.replace("eq 53", "eq 54")},
                  endpoint_impact="ipv4:NETOPS-G82-V4"))
    result = execute.preview(rt, "lab-ios", wanted)
    assert result["reason_codes"] == ["port_management_interface"], result
    assert route_read in device.queries
    assert not device.applied_blocks
