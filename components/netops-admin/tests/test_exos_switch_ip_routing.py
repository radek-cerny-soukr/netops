"""1.0.12 SWITCH-IP-ROUTING (X12, X13, X39): ExtremeXOS static routes, VLAN IP addresses with forwarding, and VRRP.

Fixtures in fixtures/exos_switch_ip_routing are real answers of EXOS-VM 33.6.1.14 (GNS3 exosvm, licence Core, verification, measurement M1 on the test VLAN switch-ip-multicast tag 3945), anonymised with
tests/support/anonymize_fixture.py (see fixtures/exos_switch_ip_routing/PROVENANCE.md): exosvm__config-<state>.out are the
modules vlan, rtmgr and vrrp of show configuration after each measured step, the other files are answers of the
check account netops-ro. The fake transport at the end only keeps the state; every check-account answer it gives
is one of these measured texts with the values of its state put in the measured places.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_exos import FakeExos
from test_access import stderr_access
from test_execute_exos import make_runtime

from netops_admin import engine, execute, exos, prediction
from netops_admin.errors import Rejected
from netops_admin.request import parse_request
from netops_core.ssh import SshError

FIXTURES = Path(__file__).parent / "fixtures" / "exos_switch_ip_routing"
FIRMWARE = "33.6.1.14"
TAIL = "#\n# Module upm configuration.\n#\n"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def config(state: str) -> bytes:
    return (fixture("exosvm__config-%s.out" % state) + TAIL).encode("utf-8")


def without(state: str, *needles) -> bytes:
    """A measured configuration without the lines holding one of the needles (the state before a step that only
    added those lines; the measurement returned to it, show configuration hash before = after)."""
    text = config(state).decode()
    return "".join(line for line in text.splitlines(keepends=True)
                   if not any(needle in line for needle in needles)).encode()


def req(table, op, key, changes=None, request_id="switch-ip-routing-0001"):
    return parse_request(request_bytes(table=table, op=op, key=key, changes=changes or {}, request_id=request_id))


def plan(snapshot: bytes, request, **options):
    return engine.build_plan("exos", snapshot, request, firmware=FIRMWARE, device="sw", **options)


def refused(snapshot, request, needle, **options):
    with pytest.raises(Rejected) as caught:
        plan(snapshot, request, **options)
    assert any(needle in reason for reason in caught.value.reasons), caught.value.reasons
    return caught.value


def match(document, snapshot, expect):
    verdict = engine.verify(document, snapshot, expect)
    return verdict["result"] == "match", verdict["differences"]


# --- show configuration parser on the measured states -------------------------------------------------------------

@pytest.mark.parametrize("state, expected", [
    ("vlan", {"tag": "3945", "description": "switch-ip-routing test"}),
    ("ipv4", {"tag": "3945", "description": "switch-ip-routing test", "ipaddress": "198.51.100.1 255.255.255.0"}),
    ("ipv4-fwd", {"tag": "3945", "description": "switch-ip-routing test", "ipaddress": "198.51.100.1 255.255.255.0",
                  "ipforwarding": "enabled"}),
    ("l3", {"tag": "3945", "description": "switch-ip-routing test", "ipaddress": "198.51.100.1 255.255.255.0",
            "ipforwarding": "enabled", "ipv6-address": "2001:db8:45::1/64", "ipforwarding-ipv6": "enabled"}),
    ("ipv4-removed", {"tag": "3945", "description": "switch-ip-routing test", "ipv6-address": "2001:db8:45::1/64",
                      "ipforwarding-ipv6": "enabled"}),
])
def test_measured_vlan_ip_lines_are_attributes(state, expected):
    snapshot = exos.load(config(state).decode(), FIRMWARE)
    entry = snapshot.vlans["switch-ip-multicast"]
    assert entry.attributes == expected and entry.unsupported == []
    # the IP lines belong to the VLAN: they are no references and stay out of the rest of the configuration
    assert snapshot.references("vlan", "switch-ip-multicast") == []


@pytest.mark.parametrize("state, reason", [
    ("ipv6-two", "a second ipv6-address"),
    ("ipv6-removed", "IPv6 link-local address without an IPv6 address"),
    ("linklocal", "IPv6 link-local address without an IPv6 address"),
])
def test_measured_states_outside_the_profile_are_unsupported(state, reason):
    entry = exos.load(config(state).decode(), FIRMWARE).vlans["switch-ip-multicast"]
    assert any(reason in item for item in entry.unsupported), entry.unsupported


def test_other_lab_vlans_and_mgmt_keep_their_addresses():
    snapshot = exos.load(config("l3").decode(), FIRMWARE)
    interfaces = exos.vlan_interfaces(snapshot)
    assert interfaces["Mgmt"]["vr"] == "VR-Mgmt" and str(interfaces["Mgmt"]["ipv4"][0]) == "192.0.2.54/25"
    assert str(interfaces["D10"]["ipv4"][0]) == "192.0.2.132/27"
    assert snapshot.vlans["D10"].attributes == {"tag": "10", "ipaddress": "192.0.2.132 255.255.255.224"}


def test_measured_routes_are_entries():
    snapshot = exos.load(config("routes").decode(), FIRMWARE)
    entries = snapshot.entries("iproute")
    assert {key: entry.attributes for key, entry in entries.items()} == {
        "vr:VR-Mgmt:0.0.0.0/0": {"gateway": "192.0.2.1"},
        "203.0.113.0/24": {"gateway": "198.51.100.254"},
        "203.0.113.128/25": {"gateway": "198.51.100.253"},
        "2001:db8:4545::/64": {"gateway": "2001:db8:45::fe"},
        "2001:db8:4546::/64": {"gateway": "2001:db8:45::fd"},
    }
    assert all(entry.unsupported == [] for entry in entries.values())
    two = exos.load(config("routes-two-gw").decode(), FIRMWARE).entries("iproute")["203.0.113.0/24"]
    assert any("a second gateway" in item for item in two.unsupported)


def test_measured_vrrp_states_are_entries():
    created = exos.load(config("vrrp-created").decode(), FIRMWARE).entries("vrrp")["switch-ip-multicast:45"]
    assert created.attributes == {"admin-state": "disabled"} and created.unsupported == []
    full = exos.load(config("vrrp").decode(), FIRMWARE).entries("vrrp")["switch-ip-multicast:45"]
    assert full.attributes == {"admin-state": "enabled", "priority": "200", "virtual-ip": "198.51.100.254"}
    vip2 = exos.load(config("vrrp-vip2").decode(), FIRMWARE).entries("vrrp")["switch-ip-multicast:45"]
    assert vip2.attributes == {"admin-state": "enabled", "virtual-ip": "198.51.100.253"}
    text = config("vrrp").decode().replace("enable vrrp vlan switch-ip-multicast vrid 45",
                                           "configure vrrp vlan switch-ip-multicast vrid 45 add track-vlan D10")
    tracked = exos.load(text, FIRMWARE).entries("vrrp")["switch-ip-multicast:45"]
    assert tracked.unsupported


# --- check account parsers on measured answers --------------------------------------------------------------------

@pytest.mark.parametrize("state, expected", [
    ("vlan", {"tag": "3945", "description": "switch-ip-routing test"}),
    ("ipv4-fwd", {"tag": "3945", "description": "switch-ip-routing test", "ipaddress": "198.51.100.1 255.255.255.0",
                  "ipforwarding": "enabled"}),
    ("l3", {"tag": "3945", "description": "switch-ip-routing test", "ipaddress": "198.51.100.1 255.255.255.0",
            "ipforwarding": "enabled", "ipv6-address": "2001:db8:45::1/64", "ipforwarding-ipv6": "enabled"}),
    ("ipv4-removed", {"tag": "3945", "description": "switch-ip-routing test", "ipv6-address": "2001:db8:45::1/64",
                      "ipforwarding-ipv6": "enabled"}),
    ("ipv6-removed", {"tag": "3945", "description": "switch-ip-routing test", "ipforwarding-ipv6": "enabled"}),
])
def test_check_account_reads_the_vlan_ip_state(state, expected):
    assert exos.shown_vlan(fixture("exosvm__show-vlan-switch_ip_multicast__%s.out" % state), "switch-ip-multicast") == expected
    assert exos.shown_vlan(fixture("exosvm__show-vlan-switch_ip_multicast__absent.out"), "switch-ip-multicast") is None


def test_check_account_reads_routes_and_refuses_an_incomplete_list():
    text = fixture("exosvm__show-iproute-vr-VR-Default__routes-two-gw.out")
    assert exos.shown_route(text, "203.0.113.0/24") == {"gateway": "198.51.100.253 198.51.100.254"}
    assert exos.shown_route(text, "203.0.113.128/25") == {"gateway": "198.51.100.253"}
    assert exos.shown_route(text, "198.51.100.0/24") is None          # direct route, not static
    assert exos.shown_route(fixture("exosvm__show-iproute__base.out"), "203.0.113.0/24") is None
    six = fixture("exosvm__show-iproute-ipv6__routes.out")
    assert exos.shown_route(six, "2001:db8:4545::/64") == {"gateway": "2001:db8:45::fe"}
    assert exos.shown_route(fixture("exosvm__show-iproute-ipv6__base.out"), "2001:db8:4545::/64") is None
    mgmt = fixture("exosvm__show-iproute-vr-VR-Mgmt__routes-two-gw.out")
    assert exos.shown_route(mgmt, "vr:VR-Mgmt:0.0.0.0/0") == {"gateway": "192.0.2.1"}
    cut = "".join(line for line in text.splitlines(keepends=True) if "203.0.113.128/25" not in line)
    with pytest.raises(Rejected, match="lists 7 routes, not 8"):
        exos.shown_route(cut, "203.0.113.0/24")
    with pytest.raises(Rejected, match="not recognised"):
        exos.shown_route(text.split("Origin(Ori)")[0], "203.0.113.0/24")


def test_check_account_reads_vrrp():
    assert exos.shown_vrrp(fixture("exosvm__show-vrrp-vlan-switch_ip_multicast__vrrp.out"), "switch-ip-multicast:45") == {
        "admin-state": "enabled", "priority": "200", "virtual-ip": "198.51.100.254"}
    assert exos.shown_vrrp(fixture("exosvm__show-vrrp-vlan-switch_ip_multicast__vrrp-created.out"), "switch-ip-multicast:45") == {
        "admin-state": "disabled", "priority": "100"}
    assert exos.shown_vrrp(fixture("exosvm__show-vrrp-vlan-switch_ip_multicast__vrrp-vip2.out"), "switch-ip-multicast:45") == {
        "admin-state": "enabled", "priority": "100", "virtual-ip": "198.51.100.253"}
    assert exos.shown_vrrp(fixture("exosvm__show-vrrp-vlan-switch_ip_multicast__vrrp.out"), "switch-ip-multicast:46") is None
    for state in ("vrrp-deleted", "absent"):
        assert exos.shown_vrrp(fixture("exosvm__show-vrrp-vlan-switch_ip_multicast__%s.out" % state), "switch-ip-multicast:45") is None
        assert exos.vrrp_absent_from_list(fixture("exosvm__show-vrrp__%s.out" % state), "switch-ip-multicast:45")
    listed = fixture("exosvm__show-vrrp__vrrp.out")
    assert not exos.vrrp_absent_from_list(listed, "switch-ip-multicast:45")
    assert exos.vrrp_absent_from_list(listed, "switch-ip-multicast:46")
    # a list cut off before its total is not read as "absent"
    assert not exos.vrrp_absent_from_list(listed.split("Total number")[0], "switch-ip-multicast:46")


def test_session_clients_are_read_from_the_measured_list():
    text = fixture("exosvm__show-session__baseline.out")
    assert exos.session_addresses(text) == [ipaddress.ip_address("192.0.2.36")]
    with pytest.raises(Rejected):
        exos.session_addresses(text.replace("192.0.2.36", "console"))


# --- X13: VLAN IP address and forwarding --------------------------------------------------------------------------

def test_ipv4_address_and_forwarding_on_an_existing_vlan():
    document = plan(config("vlan"), req("vlan", "update", "switch-ip-multicast", {"ipaddress": "198.51.100.1/24",
                                                                   "ipforwarding": "enabled"}))
    assert document["commands"] == ["configure vlan switch-ip-multicast ipaddress 198.51.100.1/24", "enable ipforwarding vlan switch-ip-multicast"]
    # measured: unconfigure removes the address and disables IPv4 forwarding
    assert document["inverse"] == ["unconfigure vlan switch-ip-multicast ipaddress"]
    assert document["firmware_support"]["status"] == "tested"
    assert match(document, config("ipv4-fwd"), "after") == (True, [])
    assert match(document, config("vlan"), "before") == (True, [])
    assert not match(document, config("ipv4"), "after")[0]


def test_a_changed_ipv4_address_is_unconfigured_first_and_forwarding_returns():
    document = plan(config("ipv4-fwd"), req("vlan", "update", "switch-ip-multicast", {"ipaddress": "198.51.100.2 255.255.255.0"}))
    assert document["commands"] == ["unconfigure vlan switch-ip-multicast ipaddress", "configure vlan switch-ip-multicast ipaddress 198.51.100.2/24",
                                    "enable ipforwarding vlan switch-ip-multicast"]
    assert document["inverse"] == ["unconfigure vlan switch-ip-multicast ipaddress", "configure vlan switch-ip-multicast ipaddress 198.51.100.1/24",
                                   "enable ipforwarding vlan switch-ip-multicast"]


def test_forwarding_is_switched_alone():
    document = plan(config("ipv4-fwd"), req("vlan", "update", "switch-ip-multicast", {"ipforwarding": "disabled"}))
    assert document["commands"] == ["disable ipforwarding vlan switch-ip-multicast"]
    assert document["inverse"] == ["enable ipforwarding vlan switch-ip-multicast"]
    assert match(document, config("ipv4"), "after") == (True, [])


def test_create_and_delete_of_a_vlan_with_its_ip_attributes():
    changes = {"tag": 3945, "description": "switch-ip-routing test", "ipaddress": "198.51.100.1/24", "ipforwarding": "enabled",
               "ipv6-address": "2001:DB8:45::1/64", "ipforwarding-ipv6": "enabled"}
    created = plan(config("base"), req("vlan", "create", "switch-ip-multicast", changes))
    assert created["commands"] == [
        "create vlan switch-ip-multicast tag 3945", 'configure vlan switch-ip-multicast description "switch-ip-routing test"',
        "configure vlan switch-ip-multicast ipaddress 198.51.100.1/24", "enable ipforwarding vlan switch-ip-multicast",
        "configure vlan switch-ip-multicast ipaddress 2001:db8:45::1/64", "enable ipforwarding ipv6 vlan switch-ip-multicast"]
    assert created["inverse"] == ["delete vlan switch-ip-multicast"]
    # measured: the commands in this order give exactly the l3 state (hash s5 = s13 = s25)
    assert match(created, config("l3"), "after") == (True, [])
    assert match(created, config("base"), "before") == (True, [])
    deleted = plan(config("l3"), req("vlan", "delete", "switch-ip-multicast"))
    assert deleted["commands"] == ["delete vlan switch-ip-multicast"]
    assert deleted["inverse"] == created["commands"]
    assert match(deleted, config("base"), "after") == (True, [])


def test_the_predicted_configuration_holds_the_ip_lines():
    document = plan(config("vlan"), req("vlan", "update", "switch-ip-multicast", {"ipaddress": "198.51.100.1/24",
                                                                   "ipforwarding": "enabled"}))
    predicted = exos.load(prediction.snapshot_after(config("vlan").decode(), document), FIRMWARE)
    assert predicted.vlans["switch-ip-multicast"].attributes == document["predicted"]["after"]


def test_ipv6_address_is_replaced_but_not_added_or_removed_on_an_existing_vlan():
    document = plan(config("l3"), req("vlan", "update", "switch-ip-multicast", {"ipv6-address": "2001:db8:45::2/64"}))
    # measured: a second IPv6 address is added, so the new one comes first and the old one is removed
    assert document["commands"] == ["configure vlan switch-ip-multicast ipaddress 2001:db8:45::2/64",
                                    "unconfigure vlan switch-ip-multicast ipaddress 2001:db8:45::1/64"]
    refused(config("vlan"), req("vlan", "update", "switch-ip-multicast", {"ipv6-address": "2001:db8:45::1/64"}), "link-local")
    refused(config("l3"), req("vlan", "update", "switch-ip-multicast", {"ipv6-address": None, "ipforwarding-ipv6": None}),
            "link-local")


@pytest.mark.parametrize("changes, reason", [
    ({"ipforwarding": "enabled"}, "IPv4 forwarding needs an IPv4 address"),
    ({"ipaddress": "192.0.2.137/27"}, "overlaps 192.0.2.132/27 of VLAN D10"),
    ({"ipaddress": "192.0.2.100/25"}, "of VLAN Mgmt"),
    ({"ipaddress": "198.51.100.0/24"}, "usable host address"),
    ({"ipaddress": "198.51.100.1/31"}, "usable host address"),
    ({"ipv6-address": "fe80::1/64"}, "global IPv6 address"),
])
def test_vlan_ip_refusals(changes, reason):
    refused(config("vlan"), req("vlan", "update", "switch-ip-multicast", changes), reason)


def test_the_ipv4_address_under_vrrp_or_a_route_gateway_is_kept():
    refused(config("vrrp"), req("vlan", "update", "switch-ip-multicast", {"ipaddress": "198.51.100.2/24"}), "carries VRRP")
    refused(config("routes"), req("vlan", "update", "switch-ip-multicast", {"ipaddress": None, "ipforwarding": None}),
            "static route 203.0.113.0/24, 203.0.113.128/25 uses a gateway")
    refused(config("routes"), req("vlan", "delete", "switch-ip-multicast"), "uses a gateway")
    refused(config("vrrp"), req("vlan", "delete", "switch-ip-multicast"), "referenced")


def test_ip_attributes_on_another_firmware_carry_the_untested_warning():
    document = engine.build_plan("exos", config("vlan"), req("vlan", "update", "switch-ip-multicast", {"ipaddress": "198.51.100.1/24"}),
                                 firmware="33.7.1.6", device="sw")
    assert document["firmware_support"]["status"] != "tested"
    assert "not among the tested versions" in document["prechecks"][0]
    plain = engine.build_plan("exos", config("vlan"), req("vlan", "update", "switch-ip-multicast", {"description": "x"}),
                              firmware="33.7.1.6", device="sw")
    assert plain["firmware_support"]["status"] == "tested"


# --- X12: static routes -------------------------------------------------------------------------------------------

ROUTE_LINE = "configure iproute add 203.0.113.0 255.255.255.0 198.51.100.254"
ROUTE6_LINE = "configure iproute add 2001:db8:4545::/64 2001:db8:45::fe"


def test_route_create_matches_the_measured_line():
    before = without("routes", ROUTE_LINE)
    document = plan(before, req("iproute", "create", "203.0.113.0/24", {"gateway": "198.51.100.254"}))
    assert document["commands"] == ["configure iproute add 203.0.113.0/24 198.51.100.254"]
    assert document["inverse"] == ["configure iproute delete 203.0.113.0/24 198.51.100.254"]
    assert match(document, config("routes"), "after") == (True, [])
    assert match(document, before, "before") == (True, [])
    predicted = exos.load(prediction.snapshot_after(before.decode(), document), FIRMWARE)
    assert predicted.entries("iproute")["203.0.113.0/24"].attributes == {"gateway": "198.51.100.254"}


def test_ipv6_route_and_explicit_vr_default():
    before = without("routes", ROUTE6_LINE)
    document = plan(before, req("iproute", "create", "2001:db8:4545::/64", {"gateway": "2001:DB8:45::FE"}))
    assert document["commands"] == ["configure iproute add 2001:db8:4545::/64 2001:db8:45::fe"]
    assert match(document, config("routes"), "after") == (True, [])
    refused(before, req("iproute", "create", "vr:VR-Default:2001:db8:4545::/64", {"gateway": "2001:db8:45::fe"}),
            "must be written as 2001:db8:4545::/64")


def test_a_new_gateway_is_added_before_the_old_route_is_deleted():
    document = plan(config("routes"), req("iproute", "update", "203.0.113.0/24", {"gateway": "198.51.100.253"}))
    assert document["commands"] == ["configure iproute add 203.0.113.0/24 198.51.100.253",
                                    "configure iproute delete 203.0.113.0/24 198.51.100.254"]
    assert document["inverse"] == ["configure iproute add 203.0.113.0/24 198.51.100.254",
                                   "configure iproute delete 203.0.113.0/24 198.51.100.253"]
    # the measured intermediate state holds both gateways: it is neither the state before nor after
    assert not match(document, config("routes-two-gw"), "after")[0]
    deleted = plan(config("routes"), req("iproute", "delete", "203.0.113.128/25"))
    assert deleted["commands"] == ["configure iproute delete 203.0.113.128/25 198.51.100.253"]
    assert deleted["inverse"] == ["configure iproute add 203.0.113.128/25 198.51.100.253"]


def test_default_route_in_a_user_vr_and_its_measured_form():
    text = config("routes").decode().replace(TAIL, "create virtual-router VR-SWITCH-IP-ROUTING\n" + TAIL)
    document = plan(text.encode(), req("iproute", "create", "vr:VR-SWITCH-IP-ROUTING:0.0.0.0/0", {"gateway": "203.0.113.1"}))
    assert document["commands"] == ["configure iproute add default 203.0.113.1 vr VR-SWITCH-IP-ROUTING"]
    predicted = prediction.snapshot_after(text, document)
    assert "configure iproute add default 203.0.113.1 vr VR-SWITCH-IP-ROUTING" in predicted


@pytest.mark.parametrize("key, changes, reason", [
    ("vr:VR-Mgmt:198.51.100.0/24", {"gateway": "192.0.2.1"}, "management or control path"),
    ("vr:VR-X:198.51.100.0/24", {"gateway": "192.0.2.1"}, "virtual router VR-X does not exist"),
    ("203.0.113.64/26", {"gateway": "2001:db8:45::fe"}, "not an IPv4 address"),
    ("203.0.113.64/26", {"gateway": "203.0.113.65"}, "inside the destination"),
    ("203.0.113.64/26", {"gateway": "fe80::1"}, "unicast gateway address"),
    ("203.0.113.1/24", {"gateway": "198.51.100.254"}, "without host bits"),
    ("203.0.113.0/24", {"gateway": "198.51.100.9"}, "already used"),
])
def test_route_refusals(key, changes, reason):
    refused(config("routes"), req("iproute", "create", key, changes), reason)


def test_the_measured_vr_mgmt_default_route_is_not_changed():
    refused(config("routes"), req("iproute", "update", "vr:VR-Mgmt:0.0.0.0/0", {"gateway": "192.0.2.2"}),
            "management or control path")
    refused(config("routes"), req("iproute", "delete", "vr:VR-Mgmt:0.0.0.0/0"), "management or control path")


def test_a_route_with_two_gateways_is_outside_the_profile():
    refused(config("routes-two-gw"), req("iproute", "delete", "203.0.113.0/24"), "a second gateway")


# --- X39: VRRP ------------------------------------------------------------------------------------------------------

def test_vrrp_create_update_delete_match_the_measured_states():
    created = plan(config("routes"), req("vrrp", "create", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.254",
                                                                      "priority": 200}))
    assert created["commands"] == ["create vrrp vlan switch-ip-multicast vrid 45", "configure vrrp vlan switch-ip-multicast vrid 45 priority 200",
                                   "configure vrrp vlan switch-ip-multicast vrid 45 add 198.51.100.254",
                                   "enable vrrp vlan switch-ip-multicast vrid 45"]
    assert created["inverse"] == ["delete vrrp vlan switch-ip-multicast vrid 45"]
    assert match(created, config("vrrp"), "after") == (True, [])
    assert match(created, config("routes"), "before") == (True, [])
    assert not match(created, config("vrrp-created"), "after")[0]
    updated = plan(config("vrrp"), req("vrrp", "update", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.253", "priority": None}))
    assert updated["commands"] == ["configure vrrp vlan switch-ip-multicast vrid 45 priority 100",
                                   "configure vrrp vlan switch-ip-multicast vrid 45 add 198.51.100.253",
                                   "configure vrrp vlan switch-ip-multicast vrid 45 delete 198.51.100.254"]
    assert match(updated, config("vrrp-vip2"), "after") == (True, [])
    disabled = plan(config("vrrp"), req("vrrp", "update", "switch-ip-multicast:45", {"admin-state": "disabled"}))
    assert disabled["commands"] == ["disable vrrp vlan switch-ip-multicast vrid 45"]
    deleted = plan(config("vrrp"), req("vrrp", "delete", "switch-ip-multicast:45"))
    assert deleted["commands"] == ["delete vrrp vlan switch-ip-multicast vrid 45"]
    assert deleted["inverse"] == created["commands"]
    assert match(deleted, config("routes"), "after") == (True, [])
    predicted = exos.load(prediction.snapshot_after(config("routes").decode(), created), FIRMWARE)
    assert predicted.entries("vrrp")["switch-ip-multicast:45"].attributes["virtual-ip"] == "198.51.100.254"


@pytest.mark.parametrize("snapshot, key, changes, reason", [
    ("routes", "switch-ip-multicast:45", {"virtual-ip": "203.0.113.9"}, "not a host address of the subnet"),
    ("routes", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.1"}, "address owner"),
    ("routes", "Mgmt:45", {"virtual-ip": "192.0.2.126"}, "protected"),
    ("routes", "ipv6-routing-alternate:45", {"virtual-ip": "198.51.100.254"}, "does not exist"),
    ("vlan", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.254"}, "has no IPv4 address"),
    ("routes", "switch-ip-multicast:256", {"virtual-ip": "198.51.100.254"}, "VRID of 1-255"),
    ("routes", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.254", "priority": 255}, "1..254"),
    ("vrrp", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.252"}, "already used"),
])
def test_vrrp_refusals(snapshot, key, changes, reason):
    refused(config(snapshot), req("vrrp", "create", key, changes), reason)


def test_vrrp_on_a_protected_vlan_is_refused():
    refused(config("routes"), req("vrrp", "create", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.254"}), "protected",
            protected={"vlan": ["switch-ip-multicast"]})


# --- management path ----------------------------------------------------------------------------------------------

def clients(*addresses):
    return [ipaddress.ip_address(address) for address in addresses]


MGMT_ROUTES = fixture("exosvm__show-iproute-vr-VR-Mgmt__routes-two-gw.out")        # default + Mgmt subnet
DEFAULT_ROUTES = fixture("exosvm__show-iproute-vr-VR-Default__routes-two-gw.out")  # direct + static, no default
# a route learned dynamically in VR-Default, in the measured layout of show iproute (OSPF intra-area, gateway in D10)
DYNAMIC_ROW = "*oa  192.0.2.240/28     192.0.2.129     2    UG-D---um--f- D10        0d:1h:0m:0s\n"
ACTIVE_STATIC_ROW = next(line for line in MGMT_ROUTES.splitlines(keepends=True) if line.startswith("#s"))
CLIENT_UNICAST_ROW = (ACTIVE_STATIC_ROW.replace("#s", "*s").replace("Default Route", "192.0.2.224/27")
                      .replace("192.0.2.1", "198.51.100.254").replace("Mgmt", "switch-ip-multicast"))


def with_rows(text, *rows):
    """A measured show iproute answer with more route rows (its total follows)."""
    head, rest = text.split("\n", 1)
    total = int(re.search(r"Total number of routes = (\d+)", text).group(1))
    return re.sub(r"Total number of routes = \d+", "Total number of routes = %d" % (total + len(rows)),
                  head + "\n" + "".join(rows) + rest)


def without_rows(text, needle):
    """A measured show iproute answer without the rows holding the needle (its total follows)."""
    kept = [line for line in text.splitlines(keepends=True) if needle not in line]
    total = int(re.search(r"Total number of routes = (\d+)", text).group(1))
    gone = len(text.splitlines()) - len(kept)
    return re.sub(r"Total number of routes = \d+", "Total number of routes = %d" % (total - gone), "".join(kept))


def tables(default=DEFAULT_ROUTES, mgmt=MGMT_ROUTES):
    """The route rows of show iproute vr <VR> (IPv4) of the check account, as exec_exos reads them."""
    answers = {"VR-Default": default, "VR-Mgmt": mgmt}
    return lambda vr, version: exos.route_rows(answers[vr], version)


def test_the_vr_of_the_session_comes_from_the_route_tables_of_every_vr():
    snapshot = exos.load(config("l3").decode(), FIRMWARE)
    # the measured lab: the client is outside every VLAN subnet and only VR-Mgmt holds it (its default route)
    assert exos.management_refusals(snapshot, "iproute", "0.0.0.0/0", None, {"gateway": "198.51.100.254"},
                                    clients("192.0.2.241"), tables()) == []
    assert exos.management_refusals(snapshot, "iproute", "192.0.2.224/27", None, {"gateway": "198.51.100.254"},
                                    clients("192.0.2.241"), tables()) == []
    # Review finding 2: VR-Default learns the network of the client dynamically, so the session may run in
    # VR-Default as well as in VR-Mgmt; a route that holds the client is refused (fail-closed)
    learned = tables(default=with_rows(DEFAULT_ROUTES, DYNAMIC_ROW))
    for key in ("192.0.2.224/27", "0.0.0.0/0", "192.0.2.240/28"):
        reasons = exos.management_refusals(snapshot, "iproute", key, None, {"gateway": "198.51.100.254"},
                                           clients("192.0.2.241"), learned)
        assert reasons and "cannot be determined" in reasons[0] and "VR-Default, VR-Mgmt" in reasons[0], reasons
    reasons = exos.management_refusals(snapshot, "iproute", "192.0.2.240/28", {"gateway": "192.0.2.129"}, None,
                                       clients("192.0.2.241"), learned)
    assert reasons and "cannot be determined" in reasons[0]
    # a route that does not hold the client needs no VR of the session
    assert exos.management_refusals(snapshot, "iproute", "203.0.113.0/24", None, {"gateway": "198.51.100.254"},
                                    clients("192.0.2.241"), learned) == []


def test_a_route_or_subnet_that_would_take_the_client_path_is_refused():
    snapshot = exos.load(config("l3").decode(), FIRMWARE)
    client = clients("198.51.100.77")          # a client in the subnet of switch-ip-multicast (VR-Default)
    active = DEFAULT_ROUTES.replace(" d   198.51.100.0/24", "#d   198.51.100.0/24").replace(
        "-------um---- switch-ip-multicast", "U------um--f- switch-ip-multicast")
    # only VR-Default holds the client (a VR-Mgmt without its default route): the VR of the session is known
    alone = tables(default=active, mgmt=without_rows(MGMT_ROUTES, "Default Route"))
    assert exos.management_refusals(snapshot, "iproute", "198.51.100.64/26", None, {"gateway": "192.0.2.129"},
                                    client, alone)
    assert exos.management_refusals(snapshot, "iproute", "0.0.0.0/0", None, {"gateway": "192.0.2.129"},
                                    client, alone) == []
    reasons = exos.management_refusals(snapshot, "vlan", "switch-ip-multicast", {"ipaddress": "198.51.100.1 255.255.255.0"},
                                       {"ipaddress": "198.51.100.2 255.255.255.0"}, client, alone)
    assert reasons and "carries the session" in reasons[0]
    reasons = exos.management_refusals(snapshot, "vlan", "D20", {}, {"ipaddress": "198.51.100.65 255.255.255.192"},
                                       client, alone)
    assert reasons and "would take the path" in reasons[0]
    # with the measured default route of VR-Mgmt both VRs hold the client: refused as undetermined
    reasons = exos.management_refusals(snapshot, "iproute", "198.51.100.64/26", None, {"gateway": "192.0.2.129"},
                                       client, tables(default=active))
    assert reasons and "cannot be determined" in reasons[0]
    # without any route to the client in any VR the VR of the session is unknown as well
    nowhere = tables(mgmt=without_rows(MGMT_ROUTES, "Default Route"), default=without_rows(DEFAULT_ROUTES, "switch-ip-multicast"))
    assert exos.management_refusals(snapshot, "iproute", "0.0.0.0/0", None, {"gateway": "192.0.2.129"},
                                    clients("192.0.2.241"), nowhere)


def test_a_route_that_carries_the_client_is_not_changed():
    text = config("routes").decode().replace(TAIL, "configure iproute add 192.0.2.224 255.255.255.224 198.51.100.254\n" + TAIL)
    snapshot = exos.load(text, FIRMWARE)
    alone = tables(default=with_rows(DEFAULT_ROUTES, CLIENT_UNICAST_ROW), mgmt=without_rows(MGMT_ROUTES, "Default Route"))
    reasons = exos.management_refusals(snapshot, "iproute", "192.0.2.224/27", {"gateway": "198.51.100.254"}, None,
                                       clients("192.0.2.241"), alone)
    assert reasons and "carries the session" in reasons[0]


# --- the whole Admin run through a fake transport with measured answers ---------------------------------------------

class G45Exos(FakeExos):
    """FakeExos with VLAN IP attributes, static routes and VRRP as measured on EXOS-VM 33.6.1.14."""

    def __init__(self):
        super().__init__()
        self.firmware = FIRMWARE
        self.vlans.pop("DATA")
        self.vlans["switch-ip-multicast"] = {"tag": "3945", "description": "switch-ip-routing test"}
        self.l3 = {}                       # vlan -> {"ipv4": "A/len", "fwd": bool, "ipv6": [..], "fwd6": bool}
        self.routes = {}                   # (vr, destination text) -> [gateways]
        self.vrrp = {}                     # (vlan, vrid) -> {"priority", "vips", "enabled"}
        self.ignore = None
        # 1.0.12 SWITCH-IP-ROUTING r2: the session client of show session, and rows of other origins (dynamic routes) per
        # (VR, IPv6) in the measured show iproute layout
        self.client = "192.0.2.9"
        self.dynamic = {}

    def answer(self, command):
        text = super().answer(command)
        if command == "show session":
            text = text.replace("dis  192.0.2.9", "dis  %s" % self.client)
        return text

    def _command(self, words, automatic):
        if self.ignore is not None and " ".join(words) == self.ignore and not automatic:
            return True
        if words[:2] == ["configure", "vlan"] and len(words) == 5 and words[3] == "name":
            # measured (SWITCH-REST, SWITCH-IP-ROUTING r2 M2): the rename carries the IP lines and VRRP of the VLAN
            old, new = words[2], words[4]
            if old not in self.vlans or new in self.vlans:
                return False
            self.vlans = {new if name == old else name: value for name, value in self.vlans.items()}
            if old in self.l3:
                self.l3[new] = self.l3.pop(old)
            self.vrrp = {(new if vlan == old else vlan, vrid): state for (vlan, vrid), state in self.vrrp.items()}
        elif words[:2] == ["configure", "vlan"] and len(words) == 5 and words[3] == "ipaddress":
            state = self.l3.setdefault(words[2], {"ipv4": None, "fwd": False, "ipv6": [], "fwd6": False})
            if ":" in words[4]:
                state["ipv6"].append(words[4])
            elif state["ipv4"] is not None:
                return False             # measured: Can't change primary IP Address
            else:
                state["ipv4"] = words[4]
        elif words[:2] == ["unconfigure", "vlan"] and words[3:4] == ["ipaddress"]:
            state = self.l3.get(words[2])
            if state is None:
                return False
            if len(words) == 4:
                if state["ipv4"] is None:
                    return False
                state["ipv4"], state["fwd"] = None, False      # measured: forwarding goes with the address
            elif words[4] in state["ipv6"]:
                state["ipv6"].remove(words[4])
            else:
                return False
        elif words[:2] in (["enable", "ipforwarding"], ["disable", "ipforwarding"]):
            six = words[2] == "ipv6"
            name = words[-1]
            if name not in self.vlans:
                return False
            state = self.l3.setdefault(name, {"ipv4": None, "fwd": False, "ipv6": [], "fwd6": False})
            state["fwd6" if six else "fwd"] = words[0] == "enable"
        elif words[:2] == ["configure", "iproute"] and words[2] in ("add", "delete"):
            vr = words[words.index("vr") + 1] if "vr" in words else "VR-Default"
            destination, gateway = words[3], words[4]
            if destination == "default":
                destination = "::/0" if ":" in gateway else "0.0.0.0/0"
            gateways = self.routes.setdefault((vr, destination), [])
            if words[2] == "add":
                if gateway not in gateways:
                    gateways.append(gateway)
            elif gateway in gateways:
                gateways.remove(gateway)
            else:
                return False
            if not gateways:
                self.routes.pop((vr, destination))
        elif words[1:3] == ["vrrp", "vlan"] and len(words) >= 6:
            key = (words[3], words[5])
            if words[0] == "create":
                if key in self.vrrp or words[3] not in self.vlans:
                    return False
                self.vrrp[key] = {"priority": "100", "vips": [], "enabled": False}
            elif key not in self.vrrp:
                return False
            elif words[0] == "delete":
                self.vrrp.pop(key)
            elif words[0] in ("enable", "disable"):
                self.vrrp[key]["enabled"] = words[0] == "enable"
            elif words[6:7] == ["priority"]:
                self.vrrp[key]["priority"] = words[7]
            elif words[6:7] == ["add"]:
                self.vrrp[key]["vips"].append(words[7])
            elif words[6:7] == ["delete"] and words[7] in self.vrrp[key]["vips"]:
                self.vrrp[key]["vips"].remove(words[7])
            else:
                return False
        elif words[:2] == ["delete", "vlan"] and len(words) == 3 and words[2] in self.vlans:
            self.l3.pop(words[2], None)
            return super()._command(words, automatic)
        else:
            return super()._command(words, automatic)
        self.unsaved = True
        return True

    def snapshot(self):
        text = super().snapshot()
        lines = []
        for name, state in self.l3.items():
            if state["ipv4"]:
                interface = ipaddress.IPv4Interface(state["ipv4"])
                lines.append("configure vlan %s ipaddress %s %s" % (name, interface.ip, interface.netmask))
            if state["fwd"]:
                lines.append("enable ipforwarding vlan %s" % name)
            if state["ipv6"]:
                lines.append("configure vlan %s ipaddress eui64 fe80::/64" % name)
                lines += ["configure vlan %s ipaddress %s" % (name, item) for item in reversed(state["ipv6"])]
            if state["fwd6"]:
                lines.append("enable ipforwarding ipv6 vlan %s" % name)
        # the measured management lines of EXOS-VM (Mgmt in VR-Mgmt with its default route)
        lines.append("configure vlan Mgmt ipaddress 192.0.2.54 255.255.255.128")
        rtmgr = ["#", "# Module rtmgr configuration.", "#", "configure iproute add default 192.0.2.1 vr VR-Mgmt"]
        for (vr, destination), gateways in self.routes.items():
            network = ipaddress.ip_network(destination)
            shown = ("default" if network.prefixlen == 0 else
                     "%s %s" % (network.network_address, network.netmask) if network.version == 4 else destination)
            rtmgr += ["configure iproute add %s %s%s" % (shown, gateway, "" if vr == "VR-Default" else " vr " + vr)
                      for gateway in gateways]
        vrrp = ["#", "# Module vrrp configuration.", "#"]
        for (vlan, vrid), state in self.vrrp.items():
            vrrp.append("create vrrp vlan %s vrid %s" % (vlan, vrid))
            if state["priority"] != "100":
                vrrp.append("configure vrrp vlan %s vrid %s priority %s" % (vlan, vrid, state["priority"]))
            vrrp += ["configure vrrp vlan %s vrid %s add %s" % (vlan, vrid, vip) for vip in state["vips"]]
            if state["enabled"]:
                vrrp.append("enable vrrp vlan %s vrid %s" % (vlan, vrid))
        head, rest = text.split("#\n# Module ems", 1)
        return head + "\n".join(lines + rtmgr + vrrp) + "\n#\n# Module ems" + rest

    def check_query(self, command):
        words = command.split()
        if words[:2] == ["show", "vlan"] and len(words) == 3:
            return self._show_vlan(words[2])
        if words[:2] == ["show", "iproute"]:
            return self._show_iproute(words)
        if words[:3] == ["show", "vrrp", "vlan"]:
            return self._show_vrrp_vlan(words[3])
        if words == ["show", "vrrp"]:
            return self._show_vrrp()
        return super().check_query(command)

    def _show_vlan(self, name):
        if name not in self.vlans:
            return fixture("exosvm__show-vlan-switch_ip_multicast__absent.out").replace("switch-ip-multicast", name)
        value, state = self.vlans[name], self.l3.get(name, {})
        text = fixture("exosvm__show-vlan-switch_ip_multicast__vlan.out")
        text = text.replace("with name switch-ip-multicast", "with name %s" % name).replace("Tag 3945", "Tag %s" % value["tag"])
        text = text.replace("Description:\t switch-ip-routing test", "Description:\t %s" % value.get("description", "None"))
        text = text.replace("IPv4 Forwarding:\t Disabled",
                            "IPv4 Forwarding:\t %s" % ("Enabled" if state.get("fwd") else "Disabled"))
        if state.get("ipv4"):
            text = text.replace("    IPv4 MC Forwarding:  Disabled\n",
                                "    IPv4 MC Forwarding:  Disabled\n    Primary IP:\t\t %s\n" % state["ipv4"])
        text = text.replace("IPv6 Forwarding:\t Disabled",
                            "IPv6 Forwarding:\t %s" % ("Enabled" if state.get("fwd6") else "Disabled"))
        if state.get("ipv6"):
            rows = ["fe80::10/64 (Tentative)"] + ["%s (Tentative)" % item for item in reversed(state["ipv6"])]
            text = text.replace("IPv6:                None", "IPv6:                " + "\n\t\t\t ".join(rows))
        return text

    def _show_iproute(self, words):
        six = words[2:3] == ["ipv6"]
        vr = words[words.index("vr") + 1]
        if vr == "VR-Mgmt":
            # measured: VR-Mgmt holds the Mgmt subnet and its default route (IPv4), no IPv6 route
            if not six:
                return fixture("exosvm__show-iproute-vr-VR-Mgmt__routes-two-gw.out")
            return fixture("exosvm__show-iproute-ipv6-vr-VR-Mgmt__base.out")
        if vr not in ("VR-Default",):
            return '%% Unrecognized command:  "%s"\n%% Invalid input detected.\n' % " ".join(words)
        rows = []
        for name, state in self.l3.items():
            # direct routes of the VLAN subnets (measured layout)
            if not six and state["ipv4"]:
                interface = ipaddress.IPv4Interface(state["ipv4"])
                rows.append("#d   %-18s %-15s 1    U------um--f- %-10s 0d:0h:0m:8s\n"
                            % (interface.network, interface.ip, name))
            if six and state["ipv6"]:
                for item in state["ipv6"]:
                    interface = ipaddress.IPv6Interface(item)
                    rows.append(" d  %-44s 1    -------um---- 0d:0h:0m:7s \n    %-45s %s\n"
                                % (interface.network, interface.ip, name))
                rows.append(" d  %-44s 1    -------um---- 0d:0h:0m:49s \n    %-45s %s\n"
                            % ("fe80::%%%s/64" % name, "fe80::10", name))
        for (route_vr, destination), gateways in self.routes.items():
            if route_vr != vr or (":" in destination) != six:
                continue
            shown = destination
            if ipaddress.ip_network(destination).prefixlen == 0:
                shown = "Default route" if six else "Default Route"      # measured (M2 / M1)
            for gateway in gateways:
                if six:
                    rows.append(" s  %-44s 1    -G---S-um---- 0d:0h:0m:2s \n    %-45s switch-ip-multicast\n" % (shown, gateway))
                else:
                    rows.append(" s   %-18s %-15s 1    -G---S-um---- switch-ip-multicast       0d:0h:0m:3s\n" % (shown, gateway))
        rows += self.dynamic.get((vr, six), [])
        template = fixture("exosvm__show-iproute%s__base.out" % ("-ipv6" if six else ""))
        head, legend = template.split("\nOrigin(Ori)", 1)
        head_lines = head.splitlines(keepends=True)[:2 if six else 1]
        text = "".join(head_lines) + "".join(rows) + "\nOrigin(Ori)" + legend
        return re.sub(r"Total number of routes = \d+", "Total number of routes = %d" % len(rows), text)

    def _show_vrrp_vlan(self, vlan):
        if vlan not in self.vlans:
            return fixture("exosvm__show-vrrp-vlan-switch_ip_multicast__absent.out")
        template = fixture("exosvm__show-vrrp-vlan-switch_ip_multicast__vrrp.out")
        blocks = []
        for (name, vrid), state in self.vrrp.items():
            if name != vlan:
                continue
            text = template.replace("VLAN:  switch-ip-multicast\tVRID:  45\tVRRP:  Enabled",
                                    "VLAN:  %s\tVRID:  %s\tVRRP:  %s" % (vlan, vrid,
                                                                        "Enabled" if state["enabled"] else "Disabled"))
            text = text.replace("Priority:  200(backup)", "Priority:  %s(backup)" % state["priority"])
            text = text.replace("  198.51.100.254\n", "".join("  %s\n" % vip for vip in state["vips"]))
            blocks.append(text)
        return "".join(blocks)

    def _show_vrrp(self):
        template = fixture("exosvm__show-vrrp__vrrp.out")
        row = next(line for line in template.splitlines(keepends=True) if "(En)" in line)
        rows = [row.replace("switch-ip-multicast(En)", "%s(%s)" % (vlan, "En" if state["enabled"] else "Ds")).replace(" 0045 ", " %04d " % int(vrid))
                for (vlan, vrid), state in self.vrrp.items()]
        text = template.replace(row, "".join(rows))
        return re.sub(r"Total number of VRs : \d+", "Total number of VRs : %d" % len(rows), text)


def runtime_for(tmp_path, device):
    return make_runtime(tmp_path, device, firmware=FIRMWARE)


def apply(runtime, request):
    preview = execute.preview(runtime, "sw", request)
    assert preview["result"] == "ready", preview
    return preview, execute.apply(runtime, "sw", request, expected_plan_sha256=preview["plan_sha256"])


def undo(runtime, record):
    preview = execute.preview_undo(runtime, record["change_id"], "SWITCH-IP-ROUTING return")
    assert preview["result"] == "ready", preview
    result = execute.undo(runtime, record["change_id"], "SWITCH-IP-ROUTING return")
    assert result["result"] == "confirmed", result
    return preview, result


def test_vlan_ip_preview_apply_readback_and_undo(tmp_path):
    device = G45Exos()
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    request = req("vlan", "update", "switch-ip-multicast", {"ipaddress": "198.51.100.1/24", "ipforwarding": "enabled"})
    preview = execute.preview(runtime, "sw", request)
    assert preview["result"] == "ready" and device.applied_blocks == [] and not device.unsaved
    assert any("does not carry or take the path of the session clients (192.0.2.9)" in item
               for item in preview["prechecks"])
    record = execute.apply(runtime, "sw", request, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert device.l3["switch-ip-multicast"] == {"ipv4": "198.51.100.1/24", "fwd": True, "ipv6": [], "fwd6": False}
    assert "check_identity_passed" in [step["step"] for step in record["steps"]] and device.saves == 1
    assert exos.shown_vlan(device.check_query("show vlan switch-ip-multicast"), "switch-ip-multicast")["ipforwarding"] == "enabled"
    undo_preview, _undone = undo(runtime, record)
    assert undo_preview["commands"] == ["unconfigure vlan switch-ip-multicast ipaddress"]
    assert device.snapshot() == before and not device.profiles and not device.timers


def test_vlan_create_with_ipv6_and_undo(tmp_path):
    device = G45Exos()
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req("vlan", "create", "ipv6-routing-negative", {
        "tag": 3946, "ipaddress": "203.0.113.1/25", "ipv6-address": "2001:db8:46::1/64", "ipforwarding-ipv6": "enabled"}))
    assert record["result"] == "confirmed", record
    undo(runtime, record)
    assert device.snapshot() == before


def test_route_preview_apply_readback_and_undo(tmp_path):
    device = G45Exos()
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req("iproute", "create", "203.0.113.0/24", {"gateway": "198.51.100.254"}))
    assert record["result"] == "confirmed", record
    assert device.routes == {("VR-Default", "203.0.113.0/24"): ["198.51.100.254"]}
    _preview, changed = apply(runtime, req("iproute", "update", "203.0.113.0/24", {"gateway": "198.51.100.253"},
                                           request_id="switch-ip-routing-0002"))
    assert changed["result"] == "confirmed", changed
    assert device.routes == {("VR-Default", "203.0.113.0/24"): ["198.51.100.253"]}
    undo(runtime, changed)
    assert device.routes == {("VR-Default", "203.0.113.0/24"): ["198.51.100.254"]}
    undo(runtime, record)
    assert device.snapshot() == before


def test_ipv6_route_apply_and_undo(tmp_path):
    device = G45Exos()
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req("iproute", "create", "2001:db8:4545::/64", {"gateway": "2001:db8:45::fe"}))
    assert record["result"] == "confirmed", record
    undo(runtime, record)
    assert device.snapshot() == before


def test_vrrp_preview_apply_readback_and_undo(tmp_path):
    device = G45Exos()
    device.l3["switch-ip-multicast"] = {"ipv4": "198.51.100.1/24", "fwd": True, "ipv6": [], "fwd6": False}
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req("vrrp", "create", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.254",
                                                                       "priority": 200}))
    assert record["result"] == "confirmed", record
    assert device.vrrp == {("switch-ip-multicast", "45"): {"priority": "200", "vips": ["198.51.100.254"], "enabled": True}}
    _preview, changed = apply(runtime, req("vrrp", "update", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.253",
                                                                        "admin-state": "disabled"},
                                           request_id="switch-ip-routing-0002"))
    assert changed["result"] == "confirmed", changed
    undo(runtime, changed)
    assert device.vrrp[("switch-ip-multicast", "45")] == {"priority": "200", "vips": ["198.51.100.254"], "enabled": True}
    undo(runtime, record)
    assert device.snapshot() == before


def test_a_route_through_the_session_path_is_refused_before_any_write(tmp_path):
    device = G45Exos()
    device.l3["switch-ip-multicast"] = {"ipv4": "198.51.100.1/24", "fwd": True, "ipv6": [], "fwd6": False}
    device.client = "198.51.100.77"
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "sw", req("iproute", "create", "198.51.100.64/26", {"gateway": "192.0.2.129"}))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["port_management_interface"], preview
    assert device.applied_blocks == []


def test_a_route_in_vr_default_for_a_client_learned_there_dynamically_is_refused(tmp_path):
    """Review finding 2: the measured lab reaches the client through VR-Mgmt; when VR-Default also learns the
    network of the client, the VR of the session is not known and a route holding the client is refused."""
    device = G45Exos()
    device.client = "192.0.2.241"
    runtime = runtime_for(tmp_path, device)
    request = req("iproute", "create", "192.0.2.224/27", {"gateway": "198.51.100.254"})
    ready = execute.preview(runtime, "sw", request)
    assert ready["result"] == "ready", ready
    assert any("session clients (192.0.2.241)" in item for item in ready["prechecks"])
    device.dynamic[("VR-Default", False)] = [DYNAMIC_ROW]
    preview = execute.preview(runtime, "sw", request)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["port_management_interface"], preview
    assert any("cannot be determined" in reason for reason in preview["reasons"]), preview
    assert device.applied_blocks == [] and not device.routes


def test_a_multicast_only_route_cannot_hide_the_route_carrying_the_client(tmp_path):
    multicast = CLIENT_UNICAST_ROW.replace("*s", "@s").replace("/10", "/16").replace("-um", "--m")

    class RouteTables(G45Exos):
        def _show_iproute(self, words):
            if words[-1] == "VR-Mgmt":
                return without_rows(MGMT_ROUTES, "Default Route")
            return with_rows(DEFAULT_ROUTES, CLIENT_UNICAST_ROW, multicast)

    device = RouteTables()
    device.client = "192.0.2.241"
    device.routes[("VR-Default", "192.0.2.224/27")] = ["198.51.100.254"]
    runtime = runtime_for(tmp_path, device)

    preview = execute.preview(runtime, "sw", req("iproute", "delete", "192.0.2.224/27"))

    assert preview["result"] == "rejected" and preview["reason_codes"] == ["port_management_interface"], preview
    assert any("carries the session" in reason for reason in preview["reasons"]), preview
    unicast_row, multicast_row = exos.route_rows(with_rows(DEFAULT_ROUTES, CLIENT_UNICAST_ROW, multicast), 4)[:2]
    assert (unicast_row.preference, unicast_row.flags, unicast_row.active_unicast) == ("*", "UG---S-um--f-", True)
    assert (multicast_row.preference, multicast_row.flags, multicast_row.active_unicast) == ("@", "UG---S--m--f-", False)
    assert device.applied_blocks == []


def test_a_route_table_ssh_timeout_uses_the_management_path_reason(tmp_path, monkeypatch):
    device = G45Exos()
    device.client = "192.0.2.241"
    runtime = runtime_for(tmp_path, device)
    commands = []

    def transport(_address, _port, _user, _credential, _host_key, command, **_options):
        commands.append(command)
        if command == "show iproute vr VR-Default":
            raise SshError("ssh timed out")
        return SimpleNamespace(rc=0, stdout=device.answer(command).encode(), stderr=b"")

    handle = stderr_access(monkeypatch, {}, platform="exos")
    monkeypatch.setattr("netops_admin.access.ssh.run_command", transport)
    monkeypatch.setattr(device, "query", handle.query)
    monkeypatch.setattr(device, "check_query", handle.check_query)
    request = req("iproute", "create", "192.0.2.224/27", {"gateway": "198.51.100.254"})

    preview = execute.preview(runtime, "sw", request)

    assert commands.index("show session") < commands.index("show iproute vr VR-Default")
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["port_management_interface"], preview
    assert any("VR-Default" in reason and "timed out" in reason for reason in preview["reasons"]), preview
    assert device.applied_blocks == []


@pytest.mark.parametrize("failure", ["timeout", "missing client"])
def test_an_unreadable_session_uses_the_management_path_reason(tmp_path, monkeypatch, failure):
    device = G45Exos()
    runtime = runtime_for(tmp_path, device)
    commands = []

    def transport(_address, _port, _user, _credential, _host_key, command, **_options):
        commands.append(command)
        if command == "show session":
            if failure == "timeout":
                raise SshError("ssh timed out")
            # DERIVED: the measured table cut before the row identifying the active session.
            text = fixture("exosvm__show-session__baseline.out").split("*", 1)[0]
        else:
            text = device.answer(command)
        return SimpleNamespace(rc=0, stdout=text.encode(), stderr=b"")

    handle = stderr_access(monkeypatch, {}, platform="exos")
    monkeypatch.setattr("netops_admin.access.ssh.run_command", transport)
    monkeypatch.setattr(device, "query", handle.query)
    monkeypatch.setattr(device, "check_query", handle.check_query)
    request = req("iproute", "create", "203.0.113.0/24", {"gateway": "198.51.100.254"})

    preview = execute.preview(runtime, "sw", request)

    assert "show session" in commands
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["port_management_interface"], preview
    detail = "timed out" if failure == "timeout" else "no client address"
    assert any("session list" in reason and detail in reason for reason in preview["reasons"]), preview
    assert device.applied_blocks == []


def test_a_vrrp_enable_the_switch_ignored_is_compensated_by_the_safeguard(tmp_path):
    device = G45Exos()
    device.l3["switch-ip-multicast"] = {"ipv4": "198.51.100.1/24", "fwd": False, "ipv6": [], "fwd6": False}
    device.ignore = "enable vrrp vlan switch-ip-multicast vrid 45"
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req("vrrp", "create", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.254"}))
    assert record["result"] == "reverted" and record["reason"] == "prediction mismatch", record
    assert device.snapshot() == before and not device.profiles and not device.timers


def test_an_incomplete_route_list_of_the_check_account_is_refused_before_any_write(tmp_path):
    device = G45Exos()
    device.routes[("VR-Default", "203.0.113.128/25")] = ["198.51.100.253"]
    original = device._show_iproute
    device._show_iproute = lambda words: original(words).replace("Total number of routes = 1",
                                                                 "Total number of routes = 2")
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "sw", req("iproute", "create", "203.0.113.0/24", {"gateway": "198.51.100.254"}))
    assert preview["result"] == "rejected" and "check account" in preview["reasons"][0], preview
    assert device.applied_blocks == []


# --- Review findings (verification-r2) ----------------------------------------------------------------

@pytest.mark.parametrize("snapshot, table, op, key, changes", [
    # finding 1: a zone identifier or white space inside an address never reaches the CLI (IPv6 and IPv4 paths)
    ("routes", "iproute", "create", "2001:db8:4547::/64", {"gateway": "2001:db8:45::fe%two words"}),
    ("routes", "iproute", "create", "2001:db8:4547::/64", {"gateway": "2001:db8:45::fe%switch-ip-multicast"}),
    ("routes", "iproute", "create", "2001:db8:4547::/64", {"gateway": "2001:db8:45::fe\t"}),
    ("routes", "iproute", "create", "2001:db8:4547::/64", {"gateway": " 2001:db8:45::fe"}),
    ("routes", "iproute", "create", "203.0.113.64/26", {"gateway": "198.51.100.254 "}),
    ("routes", "iproute", "create", "203.0.113.64/26", {"gateway": "\t198.51.100.254"}),
    ("routes", "iproute", "update", "203.0.113.0/24", {"gateway": "198.51.100.253\n"}),
    ("l3", "vlan", "update", "switch-ip-multicast", {"ipv6-address": "2001:db8:45::2%two words/64"}),
    ("l3", "vlan", "update", "switch-ip-multicast", {"ipv6-address": "2001:db8:45::2%x/64"}),
    ("l3", "vlan", "update", "switch-ip-multicast", {"ipv6-address": "2001:db8:45::2/64 "}),
    ("l3", "vlan", "update", "switch-ip-multicast", {"ipv6-address": "2001:db8:45::2/ 64"}),
    ("routes", "vrrp", "create", "switch-ip-multicast:45", {"virtual-ip": "198.51.100.254 "}),
])
def test_an_address_with_a_zone_or_white_space_is_refused(snapshot, table, op, key, changes):
    with pytest.raises(Rejected) as caught:
        plan(config(snapshot), req(table, op, key, changes))
    assert any("plain address" in reason for reason in caught.value.reasons), caught.value.reasons


def test_a_zone_in_a_gateway_is_refused_before_any_write(tmp_path):
    device = G45Exos()
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "sw", req("iproute", "create", "2001:db8:4545::/64",
                                                 {"gateway": "2001:db8:45::fe%two words"}))
    assert preview["result"] == "rejected" and any("plain address" in item for item in preview["reasons"]), preview
    assert device.applied_blocks == [] and not device.routes


def test_a_vrrp_plan_is_refused_on_a_vlan_with_a_protected_port():
    """finding 3: VRRP on D10 changes D10, so a protected member port of D10 refuses it like a VLAN change."""
    l3 = config("l3")
    refused(l3, req("vlan", "update", "D10", {"description": "x"}), "protected object '1'",
            protected={"ports": ["1"]})
    refused(l3, req("vrrp", "create", "D10:45", {"virtual-ip": "192.0.2.158"}), "protected object '1'",
            protected={"ports": ["1"]})
    refused(l3, req("vrrp", "create", "D10:45", {"virtual-ip": "192.0.2.158"}), "protected object '2'",
            protected={"ports": ["2"]})
    assert plan(l3, req("vrrp", "create", "D10:45", {"virtual-ip": "192.0.2.158"}),
                protected={"ports": ["9"]})["commands"][0] == "create vrrp vlan D10 vrid 45"


def test_the_audit_policy_refuses_vrrp_on_a_vlan_with_a_protected_port():
    from netops_admin import audit_gate
    document = plan(config("l3"), req("vrrp", "create", "D10:45", {"virtual-ip": "192.0.2.158"}))
    text = prediction.snapshot_after(config("l3").decode(), document)
    with pytest.raises(Rejected, match="protected by the audit policy"):
        audit_gate.check_policy(document, {"protected_ports": ["1"]}, text)


def test_a_vrrp_change_on_a_vlan_with_a_protected_port_is_refused_before_any_write(tmp_path):
    import dataclasses
    device = G45Exos()
    device.l3["switch-ip-multicast"] = {"ipv4": "198.51.100.1/24", "fwd": False, "ipv6": [], "fwd6": False}
    device.vlans["DATA"] = {"tag": "100"}          # FakeExos: DATA holds the untagged ports 1-4
    device.l3["DATA"] = {"ipv4": "203.0.113.1/24", "fwd": False, "ipv6": [], "fwd6": False}
    runtime = runtime_for(tmp_path, device)
    runtime.config.devices["sw"] = dataclasses.replace(runtime.config.devices["sw"], protected={"ports": ["3"]})
    from enrollment_helpers import certify
    runtime = certify(runtime, device, "sw")
    preview = execute.preview(runtime, "sw", req("vrrp", "create", "DATA:45", {"virtual-ip": "203.0.113.254"}))
    assert preview["result"] == "rejected" and any("protected object '3'" in item for item in preview["reasons"]), preview
    assert execute.preview(runtime, "sw", req("vrrp", "create", "switch-ip-multicast:45",
                                              {"virtual-ip": "198.51.100.254"}))["result"] == "ready"
    assert device.applied_blocks == [] and not device.vrrp


NOVIP_PRIORITY = "configure vrrp vlan switch-ip-multicast vrid 45 priority 200"


def test_the_priority_of_a_vrrp_instance_without_a_virtual_address():
    """finding 4: the measured instance without VIP (vrrp-created) takes a priority (M2 measured the line)."""
    document = plan(config("vrrp-created"), req("vrrp", "update", "switch-ip-multicast:45", {"priority": 200}))
    assert document["commands"] == [NOVIP_PRIORITY]
    assert document["inverse"] == ["configure vrrp vlan switch-ip-multicast vrid 45 priority 100"]
    after = config("vrrp-created").replace(b"create vrrp vlan switch-ip-multicast vrid 45\n",
                                           b"create vrrp vlan switch-ip-multicast vrid 45\n" + NOVIP_PRIORITY.encode() + b"\n")
    assert match(document, after, "after") == (True, [])
    assert match(document, config("vrrp-created"), "before") == (True, [])
    predicted = exos.load(prediction.snapshot_after(config("vrrp-created").decode(), document), FIRMWARE)
    assert predicted.entries("vrrp")["switch-ip-multicast:45"].attributes == {"admin-state": "disabled", "priority": "200"}
    measured = exos.load(config("vrrp-novip-priority").decode(), FIRMWARE).entries("vrrp")["switch-ip-multicast:45"]
    assert measured.attributes == {"admin-state": "disabled", "priority": "200"} and measured.unsupported == []
    assert exos.shown_vrrp(fixture("exosvm__show-vrrp-vlan-switch_ip_multicast__vrrp-novip-priority.out"), "switch-ip-multicast:45") == {
        "admin-state": "disabled", "priority": "200"}
    # the inverse of a delete could not return the instance through a create (virtual-ip is required on create)
    refused(config("vrrp-created"), req("vrrp", "delete", "switch-ip-multicast:45"), "cannot be recreated by the inverse")


@pytest.mark.parametrize("changes, reason", [
    ({"admin-state": "enabled"}, "at least one virtual address"),
    ({"priority": 200, "admin-state": None}, "at least one virtual address"),
    ({"virtual-ip": "198.51.100.254"}, "first virtual address"),
])
def test_a_vrrp_instance_without_a_virtual_address_is_refused_readably(changes, reason):
    refused(config("vrrp-created"), req("vrrp", "update", "switch-ip-multicast:45", changes), reason)


def test_vrrp_priority_without_a_virtual_address_apply_and_undo(tmp_path):
    device = G45Exos()
    device.l3["switch-ip-multicast"] = {"ipv4": "198.51.100.1/24", "fwd": False, "ipv6": [], "fwd6": False}
    device.vrrp[("switch-ip-multicast", "45")] = {"priority": "100", "vips": [], "enabled": False}
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req("vrrp", "update", "switch-ip-multicast:45", {"priority": 200}))
    assert record["result"] == "confirmed", record
    assert device.vrrp[("switch-ip-multicast", "45")] == {"priority": "200", "vips": [], "enabled": False}
    undo(runtime, record)
    assert device.snapshot() == before


def test_a_forwarding_state_the_check_account_does_not_show_is_not_confirmed():
    """finding 5: Enabled and Disabled are read explicitly; a missing or unknown forwarding row is unreadable."""
    text = fixture("exosvm__show-vlan-switch_ip_multicast__ipv4-fwd.out")
    assert exos.shown_l3(text, strict=True)["ipforwarding"] == "enabled"
    assert "ipforwarding" not in exos.shown_l3(text.replace("IPv4 Forwarding:\t Enabled", "IPv4 Forwarding:\t Disabled"),
                                               strict=True)
    cut = "".join(line for line in text.splitlines(keepends=True) if "IPv4 Forwarding:" not in line)
    for broken in (cut, text.replace("IPv4 Forwarding:\t Enabled", "IPv4 Forwarding:\t Pending"),
                   text.replace("IPv6 Forwarding:\t Disabled", "IPv6 Forwarding:")):
        with pytest.raises(Rejected, match="forwarding"):
            exos.shown_l3(broken, strict=True)


@pytest.mark.parametrize("broken", ["missing", "unknown"])
def test_forwarding_off_without_its_readback_row_is_reverted(tmp_path, broken):
    device = G45Exos()
    device.l3["switch-ip-multicast"] = {"ipv4": "198.51.100.1/24", "fwd": True, "ipv6": [], "fwd6": False}
    original = device._show_vlan

    def answer(name):
        text = original(name)
        if device.l3.get(name, {}).get("fwd"):
            return text
        # after the write: the answer of the check account loses (or garbles) its IPv4 forwarding row
        if broken == "missing":
            return "".join(line for line in text.splitlines(keepends=True) if "IPv4 Forwarding:" not in line)
        return text.replace("IPv4 Forwarding:\t Disabled", "IPv4 Forwarding:\t Unknown")

    device._show_vlan = answer
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req("vlan", "update", "switch-ip-multicast", {"ipforwarding": "disabled"}))
    assert record["result"] != "confirmed", record
    assert "check_identity_failed" in [step["step"] for step in record["steps"]]
    assert "check_identity_passed" not in [step["step"] for step in record["steps"]]
    assert device.l3["switch-ip-multicast"]["fwd"] is True and device.snapshot() == before


RENAMED_BEFORE = config("ipv6-two-renamed").replace(b"ipv6-routing-renamed", b"switch-ip-multicast")      # M2 step 02 before the rename


@pytest.mark.parametrize("before, new", [
    (config("ipv6-two"), "switch-ip-routing-renamed"),
    (RENAMED_BEFORE, "ipv6-routing-renamed"),
    (config("linklocal"), "ipv6-routing-negative"),
], ids=["ipv6-two", "ipv6-two-measured-M2", "linklocal"])
def test_a_rename_of_a_vlan_with_ipv6_forms_outside_the_profile_is_planned(before, new):
    """finding 6: two IPv6 addresses or the automatic link-local alone limit L3 changes, not the SWITCH-REST rename."""
    document = plan(before, req("vlan", "update", "switch-ip-multicast", {"name": new}))
    assert document["commands"] == ["configure vlan switch-ip-multicast name %s" % new]
    assert document["inverse"] == ["configure vlan %s name switch-ip-multicast" % new]
    assert match(document, before, "before") == (True, [])
    # measured (M2 step 02): the rename carries every line of the VLAN, the IP lines included
    after = before.replace(b"switch-ip-multicast", new.encode())
    if new == "ipv6-routing-renamed":
        assert after == config("ipv6-two-renamed")
    assert match(document, after, "after") == (True, [])
    # a reference the switch did not rename (here an IP line left on the old name) is still a difference
    left = after.replace(b"configure vlan %s ipaddress eui64" % new.encode(), b"configure vlan switch-ip-multicast ipaddress eui64")
    assert not match(document, left, "after")[0]


def test_l3_changes_on_those_vlans_stay_refused():
    refused(config("ipv6-two"), req("vlan", "update", "switch-ip-multicast", {"ipaddress": "198.51.100.2/24"}), "a second ipv6-address")
    refused(config("linklocal"), req("vlan", "delete", "switch-ip-multicast"), "link-local")


@pytest.mark.parametrize("changes, commands", [
    ({"description": "switch-ip-routing r3"}, ['configure vlan switch-ip-multicast description "switch-ip-routing r3"']),
    ({"tagged-ports": ["7"]}, ["configure vlan switch-ip-multicast add ports 7 tagged"]),
], ids=["description", "tagged-ports"])
def test_switch_rest_vlan_updates_preserve_two_ipv6_addresses(tmp_path, changes, commands):
    before = config("ipv6-two")

    class MeasuredVlan(G45Exos):
        def snapshot(self):
            accounts, _ = super().snapshot().split("#\n# Module vlan configuration.", 1)
            return accounts + before.decode()

    device = MeasuredVlan()
    runtime = runtime_for(tmp_path, device)
    request = req("vlan", "update", "switch-ip-multicast", changes)

    preview = execute.preview(runtime, "sw", request)

    assert preview["result"] == "ready", preview
    assert preview["commands"] == commands
    document = plan(before, request, ports=device.port_numbers)
    assert match(document, before, "before") == (True, [])
    after = prediction.snapshot_after(before.decode(), document).encode()
    assert match(document, after, "after") == (True, [])
    assert not match(document, after.replace(b"2001:db8:45::2/64", b"2001:db8:45::3/64"), "after")[0]
    assert device.applied_blocks == []


def test_rename_of_a_vlan_with_two_ipv6_addresses_apply_and_undo(tmp_path):
    device = G45Exos()
    device.l3["switch-ip-multicast"] = {"ipv4": None, "fwd": False, "ipv6": ["2001:db8:4545::1/64", "2001:db8:4545::2/64"],
                         "fwd6": False}
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req("vlan", "update", "switch-ip-multicast", {"name": "ipv6-routing-renamed"}))
    assert record["result"] == "confirmed", record
    assert "ipv6-routing-renamed" in device.vlans and device.l3["ipv6-routing-renamed"]["ipv6"] == ["2001:db8:4545::1/64", "2001:db8:4545::2/64"]
    undo(runtime, record)
    assert device.snapshot() == before


DEFAULT6_LINE = "configure iproute add default 2001:db8:4545::fe"


def test_the_ipv6_default_route_matches_the_measured_forms():
    """finding 7: measured on EXOS-VM (M2): show configuration prints 'default <gw>', show iproute ipv6 a
    'Default route' row."""
    measured = exos.load(config("default6").decode(), FIRMWARE).entries("iproute")
    assert measured["::/0"].attributes == {"gateway": "2001:db8:4545::fe"} and measured["::/0"].unsupported == []
    shown = fixture("exosvm__show-iproute-ipv6-vr-VR-Default__default6.out")
    assert exos.shown_route(shown, "::/0") == {"gateway": "2001:db8:4545::fe"}
    assert exos.shown_route(shown, "2001:db8:4545::/64") is None              # direct, not static
    before = without("default6", DEFAULT6_LINE)
    document = plan(before, req("iproute", "create", "::/0", {"gateway": "2001:DB8:4545::FE"}))
    assert document["commands"] == [DEFAULT6_LINE]
    assert document["inverse"] == ["configure iproute delete default 2001:db8:4545::fe"]
    assert match(document, config("default6"), "after") == (True, [])
    assert match(document, before, "before") == (True, [])
    assert DEFAULT6_LINE in prediction.snapshot_after(before.decode(), document)
    deleted = plan(config("default6"), req("iproute", "delete", "::/0"))
    assert deleted["commands"] == ["configure iproute delete default 2001:db8:4545::fe"]
    refused(before, req("iproute", "create", "::/0", {"gateway": "198.51.100.254"}), "not an IPv6 address")


def test_ipv6_default_route_apply_readback_and_undo(tmp_path):
    device = G45Exos()
    device.l3["switch-ip-multicast"] = {"ipv4": None, "fwd": False, "ipv6": ["2001:db8:4545::1/64"], "fwd6": False}
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req("iproute", "create", "::/0", {"gateway": "2001:db8:4545::fe"}))
    assert record["result"] == "confirmed", record
    assert device.routes == {("VR-Default", "::/0"): ["2001:db8:4545::fe"]}
    assert exos.shown_route(device.check_query("show iproute ipv6 vr VR-Default"), "::/0") == {
        "gateway": "2001:db8:4545::fe"}
    undo(runtime, record)
    assert device.snapshot() == before
