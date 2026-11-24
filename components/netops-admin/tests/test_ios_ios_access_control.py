"""1.0.12 IOS-ACCESS-CONTROL (IOS-M028 ACL rules, IOS-M029 ACL attachments) on IOSv 15.9(3)M12 and IOL XE 17.18.2 over real answers.

The fixtures (fixtures/ios_ios_access_control, PROVENANCE.md) were captured on Cisco IOSv 15.9(3)M12 and Cisco IOL XE 17.18.2 in GNS3. Independent CLI sessions used a write account (privilege 15) and a check account (privilege 1). The raw measurements are private. The Helper anonymizer (tests/support/anonymize_fixture.py) processed the public captures. G64Ios
(fake_ios_acl.py) is FakeIos with that running configuration; test_the_fake_reproduces_the_measured_states compares its
configuration lines and listings with the measured ones.
"""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from enrollment_helpers import certify
from fake_ios_acl import G64Ios, fixture
from test_ios import make_runtime, steps

from netops_admin import access, engine, exec_ios, execute, ios, ios_acl
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile
from netops_admin.request import parse_request

NODES = ("iosv", "iolxe")
FW = {"iosv": "15.9(3)M12", "iolxe": "17.18.2"}
PLATFORM = {"iosv": "ios", "iolxe": "iosxe"}
PORT = {"iosv": "GigabitEthernet0/2", "iolxe": "Ethernet0/2"}
MANAGEMENT = {"iosv": "GigabitEthernet0/0", "iolxe": "Ethernet0/0"}
ACCOUNTS = ("user01", "user02")
ACL, BINDING = "ip-access-list", "interface-access-group"
V4, V6 = "NETOPS-IOS-ACCESS-CONTROL-V4", "NETOPS-IOS-ACCESS-CONTROL-V6"
V4_RULES = ("10 permit icmp any any, 20 deny ip host 198.51.100.9 any, 30 permit tcp 198.51.100.0/24 any eq 22, "
            "40 permit tcp any any eq 80, 50 permit udp any host 198.51.100.1 eq 161, 100 permit ip any any")
V6_RULES = ("10 permit icmp any any, 20 deny ipv6 host 2001:db8:1::9 any, 25 deny tcp any any eq 23, "
            "30 permit tcp 2001:db8:1::/64 any eq 22, 40 permit tcp any any eq 80, 100 permit ipv6 any any")


def measured(node, state="baseline"):
    """The snapshot of a measured state as Admin reads it: the running configuration plus the ACL listings."""
    text = fixture(node, "admin-show-running-config__%s.txt" % state)
    if re.search(r"^(?:ip|ipv6) access-list ", text, re.MULTILINE):
        text = ios_acl.with_listing(text, fixture(node, "admin-show-ip-access-lists__%s.txt" % state),
                                    fixture(node, "admin-show-ipv6-access-list__%s.txt" % state))
    return text


def req(op, table, key, changes=None, request_id="req-ios-access-control-0001", **extra):
    return parse_request(request_bytes(table=table, op=op, key=key, changes=changes or {}, request_id=request_id,
                                       **extra))


def acl_req(op, name, rules=None, family="ipv4", **extra):
    changes = {} if rules is None else {"rules": rules}
    return req(op, ACL, "%s:%s" % (family, name), changes, **extra)


def group_req(node, family, direction, acl, interface=None, **extra):
    return req("update", BINDING, "%s:%s:%s" % (interface or PORT[node], family, direction), {"acl": acl}, **extra)


def plan(node, request, state="baseline", text=None):
    return engine.build_plan(PLATFORM[node], (text or measured(node, state)).encode(), request, firmware=FW[node])


def device_info(node):
    return SimpleNamespace(platform=PLATFORM[node], firmware=FW[node], address="192.0.2.51", check_address=None,
                           protected={}, audit_policy=None)


def runtime(tmp_path, device):
    return make_runtime(tmp_path, device, accounts=ACCOUNTS)


def apply_approved(rt, change):
    preview = execute.preview(rt, "lab-ios", change)
    assert preview["result"] == "ready", preview
    return execute.apply(rt, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])


def stable(lines):
    return [line for line in lines if not line.startswith(ios.VOLATILE_HEADER)]


def block(lines, header):
    start = lines.index(header)
    end = start + 1
    while end < len(lines) and lines[end].startswith(" "):
        end += 1
    return lines[start:end]


# ---- the measured states and the fake ----

@pytest.mark.parametrize("node", NODES)
def test_the_fake_reproduces_the_measured_states(node):
    measured_acls = [line for line in fixture(node, "admin-show-running-config__acls.txt").split("\n")]
    device = G64Ios(node)
    mode = ["exec"]
    commands = ["configure terminal", "ip access-list extended NETOPS-IOS-ACCESS-CONTROL-V4", "10 permit icmp any any",
                "20 deny ip host 198.51.100.9 any", "30 permit tcp 198.51.100.0 0.0.0.255 any eq 22",
                "40 permit tcp any any eq www", "50 permit udp any host 198.51.100.1 eq snmp",
                "100 permit ip any any", "exit", "ip access-list extended NETOPS-IOS-ACCESS-CONTROL-EMPTY4", "exit",
                "ipv6 access-list NETOPS-IOS-ACCESS-CONTROL-V6", "permit icmp any any sequence 10",
                "deny ipv6 host 2001:db8:1::9 any sequence 20", "sequence 25 deny tcp any any eq telnet",
                "sequence 30 permit tcp 2001:db8:1::0/64 any eq 22", "sequence 40 permit tcp any any eq www",
                "sequence 100 permit ipv6 any any", "exit", "ipv6 access-list NETOPS-IOS-ACCESS-CONTROL-EMPTY6", "exit", "end"]
    for command in commands:
        device._line(command, mode)
    # measured: an IPv6 ACL without rules is not part of the running configuration
    assert "ipv6 access-list NETOPS-IOS-ACCESS-CONTROL-EMPTY6" not in device.lines and "ipv6 access-list NETOPS-IOS-ACCESS-CONTROL-EMPTY6" not in measured_acls
    for header in ("ip access-list extended NETOPS-IOS-ACCESS-CONTROL-V4", "ip access-list extended NETOPS-IOS-ACCESS-CONTROL-EMPTY4",
                   "ipv6 access-list NETOPS-IOS-ACCESS-CONTROL-V6"):
        assert [" ".join(line.split()) for line in block(device.lines, header)] == [
            " ".join(line.split()) for line in block(measured_acls, header)], header
    measured_v4 = {name: rows for name, rows in ios_acl.parse_listing(
        fixture(node, "admin-show-ip-access-lists__acls.txt"), "ipv4").items() if rows is not None}
    assert {name: [(seq, rule) for seq, rule in rows] for name, rows in device.acls()["ipv4"].items()
            if name in ("NETOPS-IOS-ACCESS-CONTROL-V4", "NETOPS-IOS-ACCESS-CONTROL-EMPTY4")} == {
        name: rows for name, rows in measured_v4.items() if name in ("NETOPS-IOS-ACCESS-CONTROL-V4", "NETOPS-IOS-ACCESS-CONTROL-EMPTY4")}
    for state, lines in (("bound", ["configure terminal", "interface " + PORT[node],
                                    "ip access-group NETOPS-IOS-ACCESS-CONTROL-V4 in", "ip access-group NETOPS-IOS-ACCESS-CONTROL-V4 out",
                                    "ipv6 traffic-filter NETOPS-IOS-ACCESS-CONTROL-V6 in", "exit", "end"]),):
        for command in lines:
            device._line(command, mode)
        measured_lines = fixture(node, "admin-show-running-config__%s.txt" % state).split("\n")
        assert block(device.lines, "interface " + PORT[node]) == block(measured_lines, "interface " + PORT[node])
    # the check account texts of the fake are the measured ones in the bound state
    for family, name in (("ip", "show ip interface "), ("ipv6", "show ipv6 interface ")):
        assert device.check_query(name + PORT[node]).split("\n")[3:] == fixture(
            node, "ro-show-%s-interface-%s__bound.txt" % (family, PORT[node].replace("/", "-"))).split("\n")[3:]


def test_the_measured_refusals_of_the_device_are_in_the_fixtures():
    assert "% Invalid input detected at '^' marker." in fixture("iosv", "config__ipv6-probe.txt")
    assert "% Duplicate sequence number" in fixture("iosv", "config__ipv4-probe.txt")
    assert "% Duplicate sequence number\n% Failed to add ace to access-list" in fixture("iolxe", "config__ipv4-probe.txt")
    assert ios.cli_error("x\n% Duplicate sequence number") is not None
    assert ios.cli_error("x\n% Invalid input detected at '^' marker.") is not None


@pytest.mark.parametrize("node", NODES)
def test_measured_acls_are_read_with_their_sequence_numbers(node):
    snapshot = ios.load(measured(node, "acls"), FW[node])
    acls = snapshot.entries(ACL)
    assert acls["ipv4:" + V4].attributes == {"rules": V4_RULES} and acls["ipv4:" + V4].unsupported == []
    assert acls["ipv6:" + V6].attributes == {"rules": V6_RULES} and acls["ipv6:" + V6].unsupported == []
    # an empty ACL exists and has no rules (IPv6: it is not listed at all); a missing one is not an entry
    assert acls["ipv4:NETOPS-IOS-ACCESS-CONTROL-EMPTY4"].attributes == {} and acls["ipv4:NETOPS-IOS-ACCESS-CONTROL-EMPTY4"].unsupported == []
    # an IPv6 ACL without rules does not exist in the running configuration (measured on both images)
    assert "ipv6:NETOPS-IOS-ACCESS-CONTROL-EMPTY6" not in acls and "ipv4:NETOPS-IOS-ACCESS-CONTROL-MISSING" not in acls
    # remarks, log and port ranges are outside the profile
    assert acls["ipv4:NETOPS-IOS-ACCESS-CONTROL-REMARK"].unsupported and acls["ipv4:NETOPS-IOS-ACCESS-CONTROL-OPTS"].unsupported


@pytest.mark.parametrize("node", NODES)
def test_the_listing_carries_the_numbers_that_the_configuration_omits(node):
    text = fixture(node, "admin-show-running-config__acls.txt")
    # IOS 15.9 prints no number of an IPv4 rule; without the listing the ACL cannot be read
    stripped = ios.load(text, FW[node])
    assert stripped.entries(ACL)["ipv4:" + V4].unsupported == ["ACL listing not read"]
    assert ios.load(measured(node, "acls"), FW[node]).entries(ACL)["ipv4:" + V4].attributes["rules"] == V4_RULES
    assert (node == "iolxe") == bool(re.search(r"^ 10 permit icmp any any$", text, re.MULTILINE))


@pytest.mark.parametrize("node", NODES)
def test_singular_and_plural_hit_counters_are_not_state(node):
    # measured on IOSv 15.9: "(1 match)" in the singular (the lab IP SLA of the peer hits a rule once a minute)
    listing = fixture(node, "admin-show-ip-access-lists__acls.txt").replace(
        "    10 permit icmp any any", "    10 permit icmp any any (1 match)").replace(
        "    40 permit tcp any any eq www", "    40 permit tcp any any eq www (25 matches)")
    v6 = fixture(node, "admin-show-ipv6-access-list__acls.txt").replace(
        "permit icmp any any sequence 10", "permit icmp any any (1 match) sequence 10")
    assert "(1 match)" in listing and "(25 matches)" in listing and "(1 match)" in v6
    text = ios_acl.with_listing(fixture(node, "admin-show-running-config__acls.txt"), listing, v6)
    acls = ios.load(text, FW[node]).entries(ACL)
    assert acls["ipv4:" + V4].attributes == {"rules": V4_RULES} and acls["ipv6:" + V6].attributes == {"rules": V6_RULES}
    assert ios_acl.observe_acl("Extended IP access list NETOPS-IOS-ACCESS-CONTROL-V4\n    10 permit icmp any any (1 match)\n"
                               "    20 deny ip any any (2 matches)\n", "ipv4:NETOPS-IOS-ACCESS-CONTROL-V4") == {
        "rules": "10 permit icmp any any, 20 deny ip any any"}


def test_hit_counters_of_the_listing_are_not_state():
    text = fixture("iolxe", "admin-show-ip-access-lists__baseline.txt")
    assert "(" in text and "matches)" in text
    snapshot = ios.load(measured("iolxe"), FW["iolxe"])
    assert "(" not in "".join(line for line in snapshot.lines if line.startswith(ios_acl.MARK))
    assert snapshot.entries(ACL)["ipv4:CAPTURE-PBR-ACL"].attributes["rules"] == "10 permit ip any 192.0.2.0/24"


@pytest.mark.parametrize("node", NODES)
def test_measured_attachments_are_read(node):
    snapshot = ios.load(measured(node, "bound"), FW[node])
    groups = snapshot.entries(BINDING)
    assert groups[PORT[node] + ":ipv4:in"].attributes == {"acl": V4}
    assert groups[PORT[node] + ":ipv4:out"].attributes == {"acl": V4}
    assert groups[PORT[node] + ":ipv6:in"].attributes == {"acl": V6}
    assert groups[PORT[node] + ":ipv6:out"].attributes == {}
    assert all(not entry.unsupported for entry in groups.values())
    half = ios.load(measured(node, "half-bound"), FW[node]).entries(BINDING)
    assert half[PORT[node] + ":ipv4:in"].attributes == {"acl": V4} and half[PORT[node] + ":ipv4:out"].attributes == {}


@pytest.mark.parametrize("node", NODES)
def test_check_account_answers_of_the_device(node):
    one = lambda name: fixture(node, name)
    assert ios_acl.observe_acl(one("ro-show-ip-access-lists-NETOPS-IOS-ACCESS-CONTROL-V4__acls.txt"), "ipv4:" + V4) == {"rules": V4_RULES}
    assert ios_acl.observe_acl(one("ro-show-ip-access-lists-NETOPS-IOS-ACCESS-CONTROL-EMPTY4__acls.txt"), "ipv4:NETOPS-IOS-ACCESS-CONTROL-EMPTY4") == {}
    assert ios_acl.observe_acl(one("ro-show-ip-access-lists-NETOPS-IOS-ACCESS-CONTROL-MISSING__acls.txt"), "ipv4:NETOPS-IOS-ACCESS-CONTROL-MISSING") is None
    assert ios_acl.observe_acl(one("ro-show-ipv6-access-list-NETOPS-IOS-ACCESS-CONTROL-V6__acls.txt"), "ipv6:" + V6) == {"rules": V6_RULES}
    # IPv6: an ACL without rules does not exist, a missing one lists nothing
    assert ios_acl.observe_acl(one("ro-show-ipv6-access-list-NETOPS-IOS-ACCESS-CONTROL-EMPTY6__acls.txt"), "ipv6:NETOPS-IOS-ACCESS-CONTROL-EMPTY6") is None
    assert ios_acl.observe_acl(one("ro-show-ipv6-access-list-NETOPS-IOS-ACCESS-CONTROL-MISSING__acls.txt"), "ipv6:NETOPS-IOS-ACCESS-CONTROL-MISSING") is None
    iface = PORT[node].replace("/", "-")
    key = PORT[node] + ":%s:%s"
    assert ios_acl.observe_binding(one("ro-show-ip-interface-%s__bound.txt" % iface), key % ("ipv4", "in")) == {"acl": V4}
    assert ios_acl.observe_binding(one("ro-show-ip-interface-%s__bound.txt" % iface), key % ("ipv4", "out")) == {"acl": V4}
    assert ios_acl.observe_binding(one("ro-show-ip-interface-%s__half-bound.txt" % iface), key % ("ipv4", "out")) == {}
    assert ios_acl.observe_binding(one("ro-show-ipv6-interface-%s__bound.txt" % iface), key % ("ipv6", "in")) == {"acl": V6}
    assert ios_acl.observe_binding(one("ro-show-ipv6-interface-%s__bound.txt" % iface), key % ("ipv6", "out")) == {}


@pytest.mark.parametrize("node", NODES)
def test_cut_or_foreign_check_account_answers_are_not_a_state(node):
    full = fixture(node, "ro-show-ip-access-lists-NETOPS-IOS-ACCESS-CONTROL-V4__acls.txt")
    for text in (full[:full.index("30 permit") + 10], full.replace("NETOPS-IOS-ACCESS-CONTROL-V4", "NETOPS-IOS-ACCESS-CONTROL-OTHER"),
                 fixture(node, "ro-show-ip-access-lists-NETOPS-IOS-ACCESS-CONTROL-REMARK__acls.txt").replace("10 permit ip any any", "10 remark x"),
                 'Line has invalid autocommand "show ip access-lists X"'):
        with pytest.raises(Rejected) as caught:
            ios_acl.observe_acl(text, "ipv4:" + V4)
        assert caught.value.reason_codes == ["ios_acl_readback_unreadable"]
    interface = fixture(node, "ro-show-ip-interface-%s__bound.txt" % PORT[node].replace("/", "-"))
    for text in (interface[:interface.index("Inbound")], interface.replace(PORT[node] + " is", "Other0/9 is", 1), ""):
        with pytest.raises(Rejected) as caught:
            ios_acl.observe_binding(text, PORT[node] + ":ipv4:in")
        assert caught.value.reason_codes == ["ios_acl_readback_unreadable"]


# ---- plans from the measured snapshots ----

@pytest.mark.parametrize("node", NODES)
def test_create_renders_the_measured_lines_and_the_inverse_deletes(node):
    rules = "10 permit icmp any any, 20 deny ip host 198.51.100.9 any, 30 permit tcp 198.51.100.0/24 any eq 22, 100 permit ip any any"
    p = plan(node, acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW", rules))
    assert p["commands"] == ["configure terminal", "ip access-list extended NETOPS-IOS-ACCESS-CONTROL-NEW", "10 permit icmp any any",
                             "20 deny ip host 198.51.100.9 any", "30 permit tcp 198.51.100.0 0.0.0.255 any eq 22",
                             "100 permit ip any any", "exit", "end"]
    assert p["inverse"] == ["configure terminal", "no ip access-list extended NETOPS-IOS-ACCESS-CONTROL-NEW", "end"]
    assert p["predicted"] == {"before": None, "after": {"rules": rules}}
    assert p["firmware_support"] is not None
    empty = plan(node, acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW"))
    assert empty["commands"] == ["configure terminal", "ip access-list extended NETOPS-IOS-ACCESS-CONTROL-NEW", "exit", "end"]
    assert empty["predicted"]["after"] == {}


@pytest.mark.parametrize("node", NODES)
def test_ipv6_rules_use_the_sequence_form_the_device_accepts(node):
    p = plan(node, acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW6", "10 permit icmp any any, 20 permit tcp 2001:db8:1::/64 any eq 22",
                           "ipv6"))
    assert p["commands"] == ["configure terminal", "ipv6 access-list NETOPS-IOS-ACCESS-CONTROL-NEW6", "sequence 10 permit icmp any any",
                             "sequence 20 permit tcp 2001:db8:1::/64 any eq 22", "exit", "end"]
    assert p["inverse"] == ["configure terminal", "no ipv6 access-list NETOPS-IOS-ACCESS-CONTROL-NEW6", "end"]


@pytest.mark.parametrize("node", NODES)
def test_update_sends_only_the_changed_rules_and_the_inverse_restores_the_numbers_and_order(node):
    new = V4_RULES.replace("20 deny ip host 198.51.100.9 any", "20 permit ip host 198.51.100.9 any").replace(
        ", 50 permit udp any host 198.51.100.1 eq 161", "") + ", 105 deny ip any any"
    p = plan(node, acl_req("update", V4, new), "acls")
    assert p["commands"] == ["configure terminal", "ip access-list extended " + V4, "no 20", "no 50",
                             "20 permit ip host 198.51.100.9 any", "105 deny ip any any", "exit", "end"]
    assert p["inverse"] == ["configure terminal", "ip access-list extended " + V4, "no 20", "no 105",
                            "20 deny ip host 198.51.100.9 any", "50 permit udp any host 198.51.100.1 eq 161", "exit", "end"]
    v6 = plan(node, acl_req("update", V6, V6_RULES.replace("25 deny tcp any any eq 23, ", ""), "ipv6"), "acls")
    assert v6["commands"] == ["configure terminal", "ipv6 access-list " + V6, "no sequence 25", "exit", "end"]
    assert v6["inverse"][-3:] == ["sequence 25 deny tcp any any eq 23", "exit", "end"]


@pytest.mark.parametrize("node", NODES)
def test_delete_restores_the_rules_with_their_numbers(node):
    p = plan(node, acl_req("delete", V4), "acls")
    assert p["commands"] == ["configure terminal", "no ip access-list extended " + V4, "end"]
    assert p["inverse"][:2] == ["configure terminal", "ip access-list extended " + V4]
    assert p["inverse"][2:-2] == ["10 permit icmp any any", "20 deny ip host 198.51.100.9 any",
                                  "30 permit tcp 198.51.100.0 0.0.0.255 any eq 22", "40 permit tcp any any eq 80",
                                  "50 permit udp any host 198.51.100.1 eq 161", "100 permit ip any any"]
    empty = plan(node, acl_req("delete", "NETOPS-IOS-ACCESS-CONTROL-EMPTY4"), "acls")
    assert empty["inverse"] == ["configure terminal", "ip access-list extended NETOPS-IOS-ACCESS-CONTROL-EMPTY4", "exit", "end"]


@pytest.mark.parametrize("node", NODES)
def test_the_planned_states_are_what_the_device_would_show(node):
    # the post-change readback of a measured state matches the plan that leads to it
    create = plan(node, acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-X", "10 permit icmp any any"), "baseline")
    created = G64Ios(node)
    mode = ["exec"]
    for command in create["commands"]:
        created._line(command, mode)
    assert engine.verify(create, created.snapshot().encode())["result"] == "match"
    back = engine.verify(create, measured(node).encode(), expect="before")
    assert back["result"] == "match", back


@pytest.mark.parametrize("node", NODES)
def test_attachment_lines_and_inverse(node):
    port = PORT[node]
    p = plan(node, group_req(node, "ipv4", "in", V4), "acls")
    assert p["commands"] == ["configure terminal", "interface " + port, "ip access-group %s in" % V4, "end"]
    assert p["inverse"] == ["configure terminal", "interface " + port, "no ip access-group %s in" % V4, "end"]
    v6 = plan(node, group_req(node, "ipv6", "out", V6), "acls")
    assert v6["commands"][2] == "ipv6 traffic-filter %s out" % V6
    assert v6["inverse"][2] == "no ipv6 traffic-filter %s out" % V6
    removed = plan(node, group_req(node, "ipv4", "out", None), "bound")
    assert removed["commands"][2] == "no ip access-group %s out" % V4
    assert removed["inverse"][2] == "ip access-group %s out" % V4
    assert removed["predicted"] == {"before": {"acl": V4}, "after": {}}


@pytest.mark.parametrize("node", NODES)
def test_unchanged_attachment_and_unknown_objects_are_refused(node):
    with pytest.raises(Rejected, match="changes nothing"):
        plan(node, group_req(node, "ipv4", "in", V4), "bound")
    with pytest.raises(Rejected, match="not in the running configuration"):
        plan(node, acl_req("update", "NETOPS-IOS-ACCESS-CONTROL-NOPE", "10 permit ip any any"), "acls")
    with pytest.raises(Rejected, match="already used"):
        plan(node, acl_req("create", V4, "10 permit ip any any"), "acls")


@pytest.mark.parametrize("rules,message", [
    ("permit ip any any", "need a sequence"),
    ("10 permit ip any any, 10 deny ip any any", "distinct"),
    ("10 permit ip any any, 20 permit ip any any", "same body"),
    ("10 allow ip any any", "ACL rule 10"),
    ("10 permit ipv6 any any", "ACL rule 10"),
    ("10 permit tcp any any range 80 90", "ACL rule 10"),
    ("10 permit ip any any log", "ACL rule 10"),
    ("10 permit icmp any any eq 80", "ACL rule 10"),
    ("10 permit tcp any any eq 70000", "ACL rule 10"),
    ("10 permit tcp 203.0.113.1/24 any", "ACL rule 10"),
    ("10 permit tcp 2001:db8::/64 any", "ACL rule 10"),
    ("0 permit ip any any", "distinct"),
])
def test_rule_text_outside_the_profile_is_refused_before_any_write(rules, message):
    with pytest.raises(Rejected, match=message) as caught:
        plan("iosv", acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW", rules))
    assert caught.value.reason_codes == ["ios_acl_unsupported"]


def test_ipv6_rules_must_use_ipv6_addresses_and_protocols():
    with pytest.raises(Rejected, match="ACL rule 10"):
        plan("iosv", acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW6", "10 permit ip any any", "ipv6"))
    with pytest.raises(Rejected, match="ACL rule 10"):
        plan("iosv", acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW6", "10 permit tcp 203.0.113.0/24 any", "ipv6"))


@pytest.mark.parametrize("node", NODES)
def test_acls_outside_the_profile_are_not_changed(node):
    for name in ("NETOPS-IOS-ACCESS-CONTROL-REMARK", "NETOPS-IOS-ACCESS-CONTROL-OPTS"):
        with pytest.raises(Rejected, match="outside the profile"):
            plan(node, acl_req("update", name, "10 permit ip any any"), "acls")
        with pytest.raises(Rejected, match="outside the profile"):
            plan(node, acl_req("delete", name), "acls")


@pytest.mark.parametrize("node", NODES)
def test_an_acl_that_does_not_agree_with_its_listing_is_not_changed(node):
    text = measured(node, "acls").replace("%snetops-acl ipv4 %s 50 permit udp" % ("! ", V4), "! netops-acl ipv4 %s 50 permit tcp" % V4)
    assert text != measured(node, "acls")
    with pytest.raises(Rejected, match="outside the profile"):
        plan(node, acl_req("update", V4, "10 permit ip any any"), text=text)
    cut = measured(node, "acls").replace("! netops-acl ipv4 %s 100 permit ip any any\n" % V4, "")
    assert cut != measured(node, "acls")
    with pytest.raises(Rejected, match="outside the profile"):
        plan(node, acl_req("update", V4, "10 permit ip any any"), text=cut)


@pytest.mark.parametrize("node", NODES)
def test_attached_acls_keep_their_rules_and_cannot_be_emptied_or_deleted(node):
    with pytest.raises(Rejected) as caught:
        plan(node, acl_req("delete", V4), "bound")
    assert caught.value.reason_codes == ["ios_acl_in_use"]
    with pytest.raises(Rejected) as caught:
        plan(node, req("update", ACL, "ipv4:" + V4, {"rules": None}), "bound")
    assert caught.value.reason_codes == ["ios_acl_in_use"]
    # a nonempty change of an attached ACL is planned (the live checks follow)
    assert plan(node, acl_req("update", V4, "10 permit ip any any"), "bound")["predicted"]["after"] == {
        "rules": "10 permit ip any any"}


@pytest.mark.parametrize("node", NODES)
def test_an_acl_name_that_is_already_attached_cannot_be_created_under_another_state(node):
    # the attachment of a missing ACL would become active with the creation
    text = measured(node, "baseline").replace("interface %s\n" % PORT[node], "interface %s\n ip access-group NETOPS-IOS-ACCESS-CONTROL-LATE in\n" % PORT[node])
    with pytest.raises(Rejected) as caught:
        plan(node, acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-LATE", "10 permit ip any any"), text=text)
    assert caught.value.reason_codes == ["ios_acl_in_use"]


@pytest.mark.parametrize("acl,family,code", [
    ("NETOPS-IOS-ACCESS-CONTROL-EMPTY4", "ipv4", "ios_acl_undefined"),
    ("NETOPS-IOS-ACCESS-CONTROL-MISSING", "ipv4", "ios_acl_undefined"),
    ("NETOPS-IOS-ACCESS-CONTROL-OPTS", "ipv4", "ios_acl_undefined"),
    ("NETOPS-IOS-ACCESS-CONTROL-REMARK", "ipv4", "ios_acl_undefined"),
    (V6, "ipv4", "ios_acl_undefined"),
    (V4, "ipv6", "ios_acl_undefined"),
    ("NETOPS-IOS-ACCESS-CONTROL-EMPTY6", "ipv6", "ios_acl_undefined"),
])
def test_only_an_existing_nonempty_extended_acl_of_the_family_is_attached(acl, family, code):
    with pytest.raises(Rejected) as caught:
        plan("iosv", group_req("iosv", family, "in", acl), "acls")
    assert caught.value.reason_codes == [code]


def test_interfaces_of_the_attachment_are_checked():
    node = "iosv"
    for interface, family, code in (("GigabitEthernet0/0", "ipv6", "ios_acl_unsupported"),
                                    ("GigabitEthernet0/3", "ipv4", "ios_acl_unsupported")):
        with pytest.raises(Rejected) as caught:
            plan(node, group_req(node, family, "in", V6 if family == "ipv6" else V4, interface), "acls")
        assert caught.value.reason_codes == [code]
    with pytest.raises(Rejected, match="does not match"):
        plan(node, group_req(node, "ipv4", "in", V4, "Loopback52"), "acls")
    with pytest.raises(Rejected) as caught:
        plan(node, group_req(node, "ipv4", "in", V4, "GigabitEthernet0/9"), "acls")
    assert "not a supported interface" in caught.value.reasons[0]
    port = PORT[node]
    text = measured(node, "acls").replace("interface %s\n" % port, "interface %s\n channel-group 1 mode active\n" % port)
    with pytest.raises(Rejected) as caught:
        plan(node, group_req(node, "ipv4", "in", V4), text=text)
    assert caught.value.reason_codes == ["port_lag_member"]


@pytest.mark.parametrize("node", NODES)
def test_protected_interfaces_acls_and_attachments_are_refused(node):
    port = PORT[node]
    text = measured(node, "bound").encode()
    for protected, request, code in (
            ({"interface": [port.lower()]}, group_req(node, "ipv4", "out", None), "port_protected"),
            ({"interface": [port]}, acl_req("update", V4, "10 permit ip any any"), "port_protected"),
            ({"interface-access-group": ["%s:ipv4:out" % port]}, group_req(node, "ipv4", "out", None), "port_protected"),
            ({"ip-access-list": [V4.lower()]}, acl_req("update", V4, "10 permit ip any any"), "ios_acl_in_use"),
            ({"ip-access-list": ["ipv4:" + V4]}, group_req(node, "ipv4", "out", None), "ios_acl_in_use")):
        with pytest.raises(Rejected) as caught:
            engine.build_plan(PLATFORM[node], text, request, firmware=FW[node], protected=protected)
        assert caught.value.reason_codes == [code], protected
    with pytest.raises(Rejected) as caught:
        engine.build_plan(PLATFORM[node], text, acl_req("update", V4, "10 permit ip any any"), firmware=FW[node],
                          protected={"ip-access-list": ["ipv4:" + V4.lower()]})
    assert caught.value.reason_codes == ["ios_acl_in_use"]


def test_the_name_is_looked_up_exactly_and_other_uses_are_found():
    node = "iolxe"
    snapshot = ios.load(measured(node), FW[node])
    bindings, others = ios_acl.references(snapshot, "ipv4:CAPTURE-PBR-ACL")
    assert bindings == set() and others == ["other"]
    assert ios_acl.references(snapshot, "ipv4:XE-ROUTING") == (set(), [])
    text = measured(node, "bound")
    snapshot = ios.load(text, FW[node])
    assert ios_acl.references(snapshot, "ipv4:" + V4)[0] == {(PORT[node], "in"), (PORT[node], "out")}
    assert ios_acl.references(snapshot, "ipv6:" + V4) == (set(), [])
    assert ios_acl.references(snapshot, "ipv6:" + V6)[0] == {(PORT[node], "in")}
    # DERIVED: the VTY line takes the ACL as its access-class (the lab VTY lines are not changed)
    vty = text.replace("line vty 0 4\n", "line vty 0 4\n access-class %s in\n" % V4, 1)
    assert "access-class" in vty
    assert ios_acl.references(ios.load(vty, FW[node]), "ipv4:" + V4)[1] == ["vty"]
    assert ios_acl.references(ios.load(vty, FW[node]), "ipv6:" + V4)[1] == []


def test_a_netestovana_version_is_a_warning_and_never_a_block():
    text = measured("iosv", "acls")
    p = engine.build_plan("ios", text.encode(), acl_req("update", V4, "10 permit ip any any"), firmware="15.9(3)M13")
    assert p["firmware"] == "15.9(3)M13"
    assert p["firmware_support"]["status"] == "untested" and "15.9(3)M13" in p["firmware_support"]["message"]
    tested = engine.build_plan("ios", text.encode(), acl_req("update", V4, "10 permit ip any any"), firmware=FW["iosv"])
    assert tested["firmware_support"]["status"] == "tested"


@pytest.mark.parametrize("platform", ("ios", "iosxe"))
def test_the_profiles_are_offered_for_the_measured_images(platform):
    version = FW["iosv" if platform == "ios" else "iolxe"]
    acl = find_profile(platform, ACL, version)
    assert acl.ops == ("create", "update", "delete") and acl.exact_versions and "rules" in acl.attributes
    group = find_profile(platform, BINDING, version)
    assert group.ops == ("update",) and group.attributes["acl"].pattern is not None
    assert acl.key_pattern.fullmatch("ipv4:" + V4) and not acl.key_pattern.fullmatch("ipv4:100")
    assert group.key_pattern.fullmatch("GigabitEthernet0/2.10:ipv6:out") and group.key_pattern.fullmatch("Vlan99:ipv4:in")
    assert not group.key_pattern.fullmatch("Loopback0:ipv4:in") and not group.key_pattern.fullmatch("Gi0/2:ipv4:in")


# ---- the management path ----

def test_ssh_of_the_open_sessions_must_stay_permitted():
    peers, local = {"192.0.2.66"}, {"203.0.113.51"}
    permit = "10 permit tcp 192.0.2.0/24 host 203.0.113.51 eq 22, 100 deny ip any any"
    assert ios_acl.permits_ssh(permit, peers, local, "in")
    for rules in ("10 deny ip host 192.0.2.66 any, 100 permit ip any any", "10 permit icmp any any",
                  "10 permit tcp 198.51.100.0/24 any eq 22", "10 permit tcp any any eq 80, 20 deny ip any any",
                  "10 permit udp any any eq 161"):
        assert not ios_acl.permits_ssh(rules, peers, local, "in"), rules
    # outbound: the port of the return traffic is unknown, only a rule without a port can be relied on
    assert ios_acl.permits_ssh("10 permit tcp host 203.0.113.51 any, 100 deny ip any any", peers, local, "out")
    assert not ios_acl.permits_ssh("10 permit tcp host 203.0.113.51 any eq 22, 100 deny ip any any", peers, local, "out")
    assert not ios_acl.permits_ssh("10 deny tcp any any eq 80, 20 permit ip any any", peers, local, "out")


@pytest.mark.parametrize("node", NODES)
def test_an_attachment_on_the_management_interface_must_permit_ssh(tmp_path, node):
    device = G64Ios(node, "acls")
    management = MANAGEMENT[node]
    p = plan(node, group_req(node, "ipv4", "in", V4, management,
                             endpoint_impact=management + ":ipv4:in"), "acls")
    if node == "iolxe":
        with pytest.raises(Rejected) as caught:
            exec_ios.plan_prechecks(device, device_info(node), p, measured(node, "acls"))
        assert caught.value.reason_codes == ["port_management_interface"]
    else:
        # The lab ACL ends with permit ip any any: the open sessions stay permitted.
        assert exec_ios.plan_prechecks(device, device_info(node), p, measured(node, "acls")) == []
        assert any("keeps SSH" in line for line in p["prechecks"])
    device._write("ipv4", V4, [(10, "deny ip host 192.0.2.66 any"), (100, "permit ip any any")])
    refused = plan(node, group_req(node, "ipv4", "in", V4, management), text=device.snapshot())
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, device_info(node), refused, device.snapshot())
    assert caught.value.reason_codes == ["port_management_interface"]


@pytest.mark.parametrize("node", NODES)
def test_the_management_path_refuses_an_ipv6_acl_and_an_acl_that_is_already_attached(tmp_path, node):
    device = G64Ios(node, "acls")
    text = device.snapshot()
    management = MANAGEMENT[node]
    mode = ["config"]
    # DERIVED: an IPv6 address on the management interface (the lab management interface has none)
    device.lines.insert(device._block("interface " + management)[1], " ipv6 address 2001:db8:9::51/64")
    text = device.snapshot()
    p = plan(node, group_req(node, "ipv6", "in", V6, management), text=text)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, device_info(node), p, text)
    assert caught.value.reason_codes == ["port_management_interface"]
    # an ACL that is attached to the management interface is changed only to rules that permit SSH
    bound = G64Ios(node, "acls")
    for command in ("interface " + management, "ip access-group %s in" % V4, "exit"):
        bound._line(command, mode)
    ok = plan(node, acl_req("update", V4, "10 permit tcp 192.0.2.0/24 any eq 22, 100 deny ip any any",
                            endpoint_impact="ipv4:" + V4), text=bound.snapshot())
    if node == "iolxe":
        with pytest.raises(Rejected) as caught:
            exec_ios.plan_prechecks(bound, device_info(node), ok, bound.snapshot())
        assert caught.value.reason_codes == ["port_management_interface"]
    else:
        exec_ios.plan_prechecks(bound, device_info(node), ok, bound.snapshot())
    bad = plan(node, acl_req("update", V4, "10 deny tcp 192.0.2.0/24 any eq 22, 100 permit ip any any"), text=bound.snapshot())
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(bound, device_info(node), bad, bound.snapshot())
    assert caught.value.reason_codes == ["port_management_interface"]


@pytest.mark.parametrize("node", NODES)
def test_an_acl_of_a_vty_line_or_another_feature_needs_endpoint_impact(node):
    # DERIVED: the VTY line takes the ACL as its access-class (the lab VTY lines are not changed)
    device = G64Ios(node, "acls")
    start = device.lines.index("line vty 0 4")
    device.lines[start + 1:start + 1] = [" access-class %s in" % V4]
    text = device.snapshot()
    if node == "iolxe":
        with pytest.raises(Rejected) as caught:
            plan(node, acl_req("update", V4, "10 permit tcp 192.0.2.0/24 any eq 22, 100 deny ip any any",
                               endpoint_impact="ipv4:" + V4), text=text)
        assert caught.value.reason_codes == ["ios_acl_in_use"]
        return
    permitting = plan(node, acl_req("update", V4, "10 permit tcp 192.0.2.0/24 any eq 22, 100 deny ip any any"), text=text)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, device_info(node), permitting, text)
    assert caught.value.reason_codes == ["endpoint_impact_required"]
    allowed = plan(node, acl_req("update", V4, "10 permit tcp 192.0.2.0/24 any eq 22, 100 deny ip any any",
                                 endpoint_impact="ipv4:" + V4), text=text)
    assert exec_ios.plan_prechecks(device, device_info(node), allowed, text) == []
    blocking = plan(node, acl_req("update", V4, "10 deny ip any any, 20 permit ip any any"), text=text)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, device_info(node), blocking, text)
    assert caught.value.reason_codes == ["port_management_interface"]


@pytest.mark.parametrize("impact", [None, "ipv4:CAPTURE-PBR-ACL"])
def test_xe_acl_used_by_a_route_map_is_refused(impact):
    device = G64Ios("iolxe")
    rules = "10 permit ip any 192.0.2.0/24, 20 deny ip any any"
    with pytest.raises(Rejected) as caught:
        plan("iolxe", acl_req("update", "CAPTURE-PBR-ACL", rules, endpoint_impact=impact), text=device.snapshot())
    assert caught.value.reason_codes == ["ios_acl_in_use"]


@pytest.mark.parametrize("node", NODES)
def test_an_up_interface_needs_endpoint_impact_and_a_down_one_does_not(node):
    device = G64Ios(node, "acls")
    text = device.snapshot()
    p = plan(node, group_req(node, "ipv4", "in", V4), text=text)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, device_info(node), p, text)
    assert caught.value.reason_codes == ["endpoint_impact_required"]
    q = plan(node, group_req(node, "ipv4", "in", V4, endpoint_impact="%s:ipv4:in" % PORT[node]), text=text)
    assert exec_ios.plan_prechecks(device, device_info(node), q, text) == []
    rows = device.status_rows.split("\n")
    index = next(i for i, row in enumerate(rows) if row.startswith(ios.short_name(PORT[node]) + " "))
    rows[index] = rows[index][:31] + "admin down".ljust(15) + "down".ljust(9) + rows[index][55:]
    device.status_rows = "\n".join(rows)
    r = plan(node, group_req(node, "ipv4", "in", V4), text=text)
    assert exec_ios.plan_prechecks(device, device_info(node), r, text) == []


@pytest.mark.parametrize("node", NODES)
def test_a_switchport_is_not_given_an_acl(node):
    device = G64Ios(node, "acls")
    device.query_override["show interfaces %s switchport" % PORT[node]] = (
        "Name: %s\nSwitchport: Enabled\nAdministrative Mode: static access\nOperational Mode: static access\n"
        "Access Mode VLAN: 1 (default)\n" % ios.short_name(PORT[node]))
    p = plan(node, group_req(node, "ipv4", "in", V4, endpoint_impact="%s:ipv4:in" % PORT[node]), text=device.snapshot())
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, device_info(node), p, device.snapshot())
    assert caught.value.reason_codes == ["port_unsupported_interface"]


@pytest.mark.parametrize("failure,code", [
    ("query failed: timed out", "ios_acl_read_timeout"),
    ("query failed: connection reset", "ios_acl_readback_unreadable"),
])
def test_a_failed_read_of_the_acl_checks_has_its_own_reason(failure, code):
    device = G64Ios("iosv", "acls")
    p = plan("iosv", group_req("iosv", "ipv4", "in", V4, endpoint_impact="%s:ipv4:in" % PORT["iosv"]), text=device.snapshot())

    def broken(command):
        raise AccessError(failure)

    device.query = broken
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(device, device_info("iosv"), p, G64Ios("iosv", "acls").snapshot())
    assert caught.value.reason_codes == [code]


# ---- end to end through Admin: preview without a write, apply, readback, undo ----

@pytest.mark.parametrize("node", NODES)
def test_preview_writes_nothing(tmp_path, node):
    device = G64Ios(node)
    result = execute.preview(runtime(tmp_path, device), "lab-ios", acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW", "10 permit icmp any any"))
    assert result["result"] == "ready", result
    assert device.applied_blocks == [] and device.lines == device.saved
    assert result["commands"][1] == "ip access-list extended NETOPS-IOS-ACCESS-CONTROL-NEW"


@pytest.mark.parametrize("table", [ACL, BINDING])
def test_review_3_acl_write_requires_a_preview_hash(tmp_path, table):
    node = "iosv"
    device = G64Ios(node, "acls")
    rt = runtime(tmp_path, device)
    key = "%s:ipv4:in" % PORT[node]
    change = (acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW", V4_RULES) if table == ACL
              else group_req(node, "ipv4", "in", V4, endpoint_impact=key))
    assert execute.preview(rt, "lab-ios", change)["result"] == "ready"
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab-ios", change)
    assert caught.value.reason_codes == ["plan_changed"]
    assert not device.applied_blocks


@pytest.mark.parametrize("node", NODES)
def test_review_4_management_acl_requires_impact_even_when_ssh_remains_permitted(tmp_path, node):
    device = G64Ios(node, "acls")
    rt = runtime(tmp_path, device)
    change = group_req(node, "ipv4", "in", V4, MANAGEMENT[node])
    preview = execute.preview(rt, "lab-ios", change)
    code = "port_management_interface" if node == "iolxe" else "endpoint_impact_required"
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code]
    assert not device.applied_blocks


@pytest.mark.parametrize("node", NODES)
def test_acl_and_attachment_are_applied_read_back_and_undone_to_the_baseline(tmp_path, node):
    device = G64Ios(node)
    rt = runtime(tmp_path, device)
    before = list(device.lines)
    created = apply_approved(rt, acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW", V4_RULES))
    assert created["result"] == "confirmed", (created["reason"], steps(created))
    assert device.applied_blocks[1] == created["plan"]["commands"] and device.timer is None
    assert device.acls()["ipv4"]["NETOPS-IOS-ACCESS-CONTROL-NEW"][0] == (10, "permit icmp any any")
    assert "show ip access-lists NETOPS-IOS-ACCESS-CONTROL-NEW" in device.check_queries
    key = "%s:ipv4:in" % PORT[node]
    bound = apply_approved(rt, group_req(node, "ipv4", "in", "NETOPS-IOS-ACCESS-CONTROL-NEW", request_id="req-ios-access-control-0002",
                                                   endpoint_impact=key))
    assert bound["result"] == "confirmed", (bound["reason"], steps(bound))
    assert " ip access-group NETOPS-IOS-ACCESS-CONTROL-NEW in" in device.interface(PORT[node]) or \
        "ip access-group NETOPS-IOS-ACCESS-CONTROL-NEW in" in device.interface(PORT[node])
    assert ("show ip interface " + PORT[node]) in device.check_queries
    changed = apply_approved(rt, acl_req("update", "NETOPS-IOS-ACCESS-CONTROL-NEW", V4_RULES.replace("20 deny", "20 permit"),
                                                  request_id="req-ios-access-control-0003", endpoint_impact="ipv4:NETOPS-IOS-ACCESS-CONTROL-NEW"))
    assert changed["result"] == "confirmed", (changed["reason"], steps(changed))
    for record in (changed, bound, created):
        back = execute.undo(rt, record["change_id"], "IOS-ACCESS-CONTROL return")
        assert back["result"] == "confirmed", (back["reason"], steps(back))
    assert device.lines == before


@pytest.mark.parametrize("node", NODES)
def test_the_undo_of_a_delete_and_of_an_update_restores_the_exact_rules(tmp_path, node):
    device = G64Ios(node, "acls")
    rt = runtime(tmp_path, device)
    before_lines, before_acls = list(device.lines), device.acls()
    deleted = apply_approved(rt, acl_req("delete", V4))
    assert deleted["result"] == "confirmed", (deleted["reason"], steps(deleted))
    assert V4 not in device.acls()["ipv4"]
    back = execute.undo(rt, deleted["change_id"], "IOS-ACCESS-CONTROL return")
    assert back["result"] == "confirmed", (back["reason"], steps(back))
    assert device.lines == before_lines and device.acls() == before_acls
    changed = apply_approved(rt, acl_req("update", V4, V4_RULES.replace("30 permit", "35 permit").replace(
        "40 permit", "42 permit"), request_id="req-ios-access-control-0004"))
    assert changed["result"] == "confirmed", (changed["reason"], steps(changed))
    assert [seq for seq, _ in device.acls()["ipv4"][V4]] == [10, 20, 35, 42, 50, 100]
    undone = execute.undo(rt, changed["change_id"], "IOS-ACCESS-CONTROL return")
    assert undone["result"] == "confirmed", (undone["reason"], steps(undone))
    assert device.acls() == before_acls and device.lines == before_lines


@pytest.mark.parametrize("node", NODES)
def test_ipv6_acl_rules_and_order_survive_apply_and_undo(tmp_path, node):
    device = G64Ios(node, "acls")
    rt = runtime(tmp_path, device)
    before_lines, before_acls = list(device.lines), device.acls()
    record = apply_approved(rt, acl_req("update", V6, V6_RULES.replace("25 deny tcp any any eq 23", "15 deny tcp any any eq 23"),
                                                 "ipv6"))
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert [seq for seq, _ in device.acls()["ipv6"][V6]][:3] == [10, 15, 20]
    created = apply_approved(rt, acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW6", "10 permit icmp any any", "ipv6",
                                                  request_id="req-ios-access-control-0005"))
    assert created["result"] == "confirmed", (created["reason"], steps(created))
    for item in (created, record):
        assert execute.undo(rt, item["change_id"], "IOS-ACCESS-CONTROL return")["result"] == "confirmed"
    assert device.acls() == before_acls and device.lines == before_lines


@pytest.mark.parametrize("node", NODES)
def test_an_attachment_without_endpoint_impact_on_an_up_interface_is_refused(tmp_path, node):
    device = G64Ios(node, "acls")
    result = execute.preview(runtime(tmp_path, device), "lab-ios", group_req(node, "ipv4", "in", V4))
    assert result["result"] == "rejected" and result["reason_codes"] == ["endpoint_impact_required"], result
    assert device.applied_blocks == []


@pytest.mark.parametrize("node", NODES)
def test_an_attachment_on_the_management_interface_is_applied_and_undone(tmp_path, node):
    device = G64Ios(node, "acls")
    rt = runtime(tmp_path, device)
    before = list(device.lines)
    request = group_req(node, "ipv4", "in", V4, MANAGEMENT[node],
                        endpoint_impact="%s:ipv4:in" % MANAGEMENT[node])
    if node == "iolxe":
        refused = execute.preview(rt, "lab-ios", request)
        assert refused["reason_codes"] == ["port_management_interface"]
        assert device.lines == before and not device.applied_blocks
        return
    record = apply_approved(rt, request)
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert any("keeps SSH" in line for line in record["plan"]["prechecks"])
    assert execute.undo(rt, record["change_id"], "IOS-ACCESS-CONTROL return")["result"] == "confirmed"
    assert device.lines == before


@pytest.mark.parametrize("node", NODES)
def test_a_rule_that_the_device_did_not_take_is_returned(tmp_path, node):
    device = G64Ios(node, "acls")
    rt = runtime(tmp_path, device)
    original = device._acl_line

    def lossy(line, words, mode):
        if words[:1] == ["20"] or words[:2] == ["sequence", "20"]:
            return ""
        return original(line, words, mode)

    device._acl_line = lossy
    before = list(device.lines)
    record = apply_approved(rt, acl_req("update", V4, V4_RULES.replace("20 deny", "20 permit")))
    expected = "revert-failed" if node == "iosv" else "reverted"
    assert record["result"] == expected, (record["result"], record["reason"], steps(record))
    assert "postcheck_failed" in steps(record)
    assert device.lines == before and device.timer is None


@pytest.mark.parametrize("node", NODES)
def test_a_foreign_change_next_to_the_acl_is_detected(tmp_path, node):
    device = G64Ios(node, "acls")
    rt = runtime(tmp_path, device)
    original = device._acl_line

    def with_side_effect(line, words, mode):
        answer = original(line, words, mode)
        if words == ["exit"]:
            device._write("ipv4", "NETOPS-IOS-ACCESS-CONTROL-EMPTY4", [(10, "permit ip any any")])
        return answer

    device._acl_line = with_side_effect
    record = apply_approved(rt, acl_req("update", V4, V4_RULES.replace("20 deny", "20 permit")))
    expected = "revert-failed" if node == "iosv" else "reverted"
    assert record["result"] == expected, (record["result"], record["reason"], steps(record))


@pytest.mark.parametrize("node", NODES)
def test_the_check_account_read_of_the_object_decides(tmp_path, node):
    device = G64Ios(node, "acls")
    rt = runtime(tmp_path, device)
    # the check account sees another rule list than the configuration (a truncated listing)
    full = device.listing("ipv4", V4)
    device.check_override = {"show ip access-lists " + V4: full[:full.index("30 permit") + 12]}
    result = execute.preview(rt, "lab-ios", acl_req("update", V4, "10 permit ip any any"))
    assert result["result"] == "rejected" and result["reason_codes"] == ["ios_acl_readback_unreadable"], result
    device.check_override = {"show ip access-lists " + V4: full.replace("20 deny", "20 permit")}
    result = execute.preview(rt, "lab-ios", acl_req("update", V4, "10 permit ip any any"))
    assert result["result"] == "rejected", result
    device.check_override = None
    device.check_unreadable = True
    result = execute.preview(rt, "lab-ios", acl_req("update", V4, "10 permit ip any any"))
    assert result["result"] == "rejected" and result["reason_codes"] == ["ios_acl_readback_unreadable"], result


@pytest.mark.parametrize("node", NODES)
def test_an_ipv6_acl_without_rules_does_not_exist_and_is_deleted_not_emptied(tmp_path, node):
    # measured on both images: ipv6 access-list NAME without a rule is not in the running configuration and removing the
    # last rule removes the ACL
    with pytest.raises(Rejected, match="without rules does not exist") as caught:
        plan(node, acl_req("create", "NETOPS-IOS-ACCESS-CONTROL-NEW6", None, "ipv6"))
    assert caught.value.reason_codes == ["ios_acl_unsupported"]
    with pytest.raises(Rejected, match="without rules does not exist"):
        plan(node, req("update", ACL, "ipv6:" + V6, {"rules": None}), "acls")
    device = G64Ios(node, "acls")
    rt = runtime(tmp_path, device)
    before = list(device.lines)
    deleted = apply_approved(rt, acl_req("delete", V6, None, "ipv6"))
    assert deleted["result"] == "confirmed", (deleted["reason"], steps(deleted))
    assert V6 not in device.acls()["ipv6"] and "ipv6 access-list " + V6 not in device.lines
    assert execute.undo(rt, deleted["change_id"], "IOS-ACCESS-CONTROL return")["result"] == "confirmed"
    # the device puts the first IPv6 ACL where it was; only the "!" separators are the fake's own and Admin writes the
    # network in the canonical form (the anonymiser printed "::0/64")
    assert [line for line in device.lines if not line.startswith(" ") and line != "!"] == [
        line for line in before if not line.startswith(" ") and line != "!"]
    assert device.acls()["ipv6"][V6] == [(seq, rule.replace("::0/64", "::/64"))
                                          for seq, rule in G64Ios(node, "acls").acls()["ipv6"][V6]]


def test_the_return_of_a_timer_reports_ios_15_9_ipv4_renumbering_without_saving(tmp_path):
    # measured (private measurement record): the rollback of the revert timer turned 10, 25, 100 into 10, 20, 30 on
    # IOSv 15.9 (IPv6 and IOS XE keep the numbers); the order and the rules are what the return restores
    device = G64Ios("iosv", "acls")
    rt = runtime(tmp_path, device)
    preview = execute.preview(rt, "lab-ios", acl_req("update", V4, V4_RULES.replace("20 deny", "20 permit")))
    assert any("renumbers IPv4 ACL rules" in line for line in preview["prechecks"])
    original = device._acl_line

    def lossy(line, words, mode):
        return "" if words[:1] == ["20"] else original(line, words, mode)

    device._acl_line = lossy
    record = apply_approved(rt, acl_req("update", V4, V4_RULES.replace("20 deny", "20 permit")))
    assert record["result"] == "revert-failed", (record["result"], record["reason"], steps(record))
    assert any("sequence numbers" in item for item in record["differences"])
    assert device.saves == 0
    assert [seq for seq, _ in device.acls()["ipv4"][V4]] == [10, 20, 30, 40, 50, 60]
    assert [rule for _, rule in device.acls()["ipv4"][V4]] == [rule for _, rule in G64Ios("iosv", "acls").acls()["ipv4"][V4]]


def test_the_return_check_does_not_accept_changed_rules_or_another_order():
    p = plan("iosv", acl_req("update", V4, V4_RULES.replace("20 deny", "20 permit")), "acls")
    renumbered = measured("iosv", "acls")
    for old, new in (("100 permit ip any any", "60 permit ip any any"), ("50 permit udp", "51 permit udp")):
        renumbered = renumbered.replace("! netops-acl ipv4 %s %s" % (V4, old), "! netops-acl ipv4 %s %s" % (V4, new))
    verdict = engine.verify(p, renumbered.encode(), expect="before")
    assert verdict["result"] == "mismatch" and verdict["rest_matches"]
    assert any("sequence numbers" in item for item in verdict["differences"])
    changed = measured("iosv", "acls").replace("20 deny ip host", "20 permit ip host")
    assert engine.verify(p, changed.encode(), expect="before")["result"] == "mismatch"
    # the exactness of an Admin undo is checked against the numbers (expect after)
    assert engine.verify(p, renumbered.encode(), expect="after")["result"] == "mismatch"


# ---- the snapshot of Admin ----

@pytest.mark.parametrize("node", NODES)
def test_the_snapshot_of_the_write_account_carries_the_listings(node, monkeypatch):
    text = fixture(node, "admin-show-running-config__acls.txt")
    answers = {"show running-config": text, "show ip access-lists": fixture(node, "admin-show-ip-access-lists__acls.txt"),
               "show ipv6 access-list": fixture(node, "admin-show-ipv6-access-list__acls.txt")}
    asked = []

    def query(self, credential, command, *args, **kwargs):
        asked.append(command)
        return answers[command]

    monkeypatch.setattr(access.DeviceAccess, "_query", query)
    device = SimpleNamespace(platform=PLATFORM[node], name="lab")
    taken = access.DeviceAccess.snapshot(SimpleNamespace(device=device, credential=object(), _query=lambda c, cmd: query(None, c, cmd)))
    assert asked == ["show running-config", "show ip access-lists", "show ipv6 access-list"]
    assert taken == measured(node, "acls")
    # without an ACL the listings are not read
    asked.clear()
    answers["show running-config"] = fixture(node, "admin-show-running-config__baseline.txt") if node == "iosv" else text.split("ip access-list")[0] + "end\n"
    if node == "iosv":
        access.DeviceAccess.snapshot(SimpleNamespace(device=device, credential=object(), _query=lambda c, cmd: query(None, c, cmd)))
        assert asked == ["show running-config"]


@pytest.mark.parametrize("text", ["% Invalid input", 'Line has invalid autocommand "show ip access-lists"', "garbage\nline"])
def test_a_listing_that_is_not_a_listing_is_refused(text):
    with pytest.raises(Rejected):
        ios_acl.with_listing(fixture("iosv", "admin-show-running-config__acls.txt"), text, "")
