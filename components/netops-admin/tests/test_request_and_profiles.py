from __future__ import annotations

import copy
import json

import pytest
from conftest import request_bytes

from netops_admin import profiles
from netops_admin.errors import Rejected
from netops_admin.request import MAX_REQUEST_BYTES, parse_request
from netops_admin.state import Store


def test_valid_request_parses():
    request = parse_request(request_bytes(device="fw-1"))
    assert request.op == "create"
    assert request.device == "fw-1"
    assert len(request.fingerprint()) == 64


@pytest.mark.parametrize(("raw", "fragment"), [
    (b"\xff", "UTF-8 JSON"),
    (b"[]", "JSON object"),
    (b"x" * (MAX_REQUEST_BYTES + 1), "larger than"),
])
def test_malformed_requests(raw, fragment):
    with pytest.raises(Rejected) as caught:
        parse_request(raw)
    assert fragment in caught.value.reasons[0]


@pytest.mark.parametrize(("fields", "fragment"), [
    ({"extra": 1}, "unknown ['extra']"),
    ({"op": "replace"}, "op must be one of"),
    ({"op": "execute"}, "op must be one of"),
    ({"request_id": "short"}, "request_id"),
    ({"request_id": "has space in it"}, "request_id"),
    ({"reason": " "}, "reason must be"),
    ({"reason": "r" * 501}, "longer than 500"),
    ({"user_request": "u" * 4001}, "longer than 4000"),
    ({"changes": []}, "changes must be an object"),
    ({"changes": {"Bad_Name": "x"}}, "not a CLI attribute name"),
    ({"changes": {"comment": {"invalid": "a"}}}, "string, an integer or null"),
    ({"changes": {"comment": 1.5}}, "string, an integer or null"),
    ({"changes": {"a%d" % index: "x" for index in range(17)}}, "more than 16"),
    ({"device": "has space"}, "inventory alias"),
    ({"key": ""}, "key must be"),
])
def test_invalid_requests(fields, fragment):
    with pytest.raises(Rejected) as caught:
        parse_request(request_bytes(**fields))
    assert fragment in caught.value.reasons[0]


def test_missing_field_is_refused():
    body = json.loads(request_bytes())
    del body["user_request"]
    with pytest.raises(Rejected) as caught:
        parse_request(json.dumps(body).encode())
    assert "missing ['user_request']" in caught.value.reasons[0]


def test_shipped_profiles_load():
    loaded = profiles.load_profiles()
    assert set(loaded) == {("fortios", "firewall address"), ("exos", "vlan"), ("exos", "ports"),
                           ("exos", "bootprelay"), ("exos", "dhcp-server"),
                           ("exos", "ospf"), ("exos", "ospf-area"), ("exos", "ospf-interface"),
                           ("exos", "bgp"), ("exos", "bgp-neighbor"),
                           ("fortios", "firewall addrgrp"), ("fortios", "system dhcp server/reserved-address"),
                           ("fortios", "system dns-database/dns-entry"),
                           ("fortios", "vpn ipsec phase2-interface"),
                           ("exos", "vlan-membership"), ("fortios", "firewall policy"),
                           ("fortios", "firewall service custom"), ("fortios", "firewall vip"),
                           ("fortios", "firewall ippool"), ("exos", "inline-power"), ("exos", "port-bounce"),
                           ("eos", "interface"), ("eos", "vlan-membership"), ("eos", "vlan"),
                           ("eos", "port-bounce"), ("eos", "inline-power"),
                           ("eos", "static-route"), ("eos", "l3-interface"), ("eos", "ip-routing"),
                           ("eos", "vrrp"), ("eos", "varp"), ("eos", "varp-mac"),
                           ("eos", "ip-access-list"), ("eos", "interface-access-group"),
                           ("eos", "port-channel"), ("eos", "port-channel-member"), ("eos", "mlag-port"),
                           ("eos", "mlag-peer"), ("eos", "stp-port"), ("eos", "stp-vlan"),
                           ("eos", "ntp-server"), ("eos", "syslog-host"), ("eos", "dns-server"),
                           ("eos", "system-services"), ("eos", "startup-config"),
                           ("ruckus", "wlan"), ("ruckus", "dhcp-relay"),
                           ("eos", "ospf-process"), ("eos", "ospf-network"), ("eos", "ospf-interface"),
                           ("eos", "ip-prefix-list"), ("eos", "route-map"), ("eos", "bgp-neighbor"),
                           ("eos", "dhcp-pool"), ("eos", "dhcp-relay"),
                           ("ios", "interface"), ("ios", "vlan-membership"), ("ios", "vlan"),
                           ("ios", "static-route"), ("ios", "l3-interface"), ("ios", "etherchannel-member"),
                           ("ios", "port-bounce"), ("ios", "poe-cycle"), ("ios", "inline-power"),
                           ("iosxe", "port-bounce"), ("iosxe", "poe-cycle"), ("iosxe", "inline-power"),
                           ("ios", "ip-access-list"), ("ios", "interface-access-group"),
                           ("ios", "dhcp-pool"), ("ios", "dhcp-reservation"),
                           ("ios", "dhcp-exclusion"), ("ios", "dhcp-relay"),
                           ("ios", "ntp-server"), ("ios", "syslog-host"), ("ios", "static-host"),
                           ("ios", "system-services"), ("ios", "startup-config"),
                           ("iosxe", "interface"), ("iosxe", "vlan-membership"), ("iosxe", "vlan"),
                           ("iosxe", "static-route"), ("iosxe", "l3-interface"), ("iosxe", "etherchannel-member"),
                           ("iosxe", "ip-access-list"), ("iosxe", "interface-access-group"),
                           ("iosxe", "dhcp-pool"), ("iosxe", "dhcp-reservation"),
                           ("iosxe", "dhcp-exclusion"), ("iosxe", "dhcp-relay"),
                           ("iosxe", "ntp-server"), ("iosxe", "syslog-host"), ("iosxe", "static-host"),
                           ("iosxe", "system-services"), ("iosxe", "startup-config"),
                           ("exos", "iproute"), ("exos", "vrrp"),
                           ("exos", "acl-policy"), ("exos", "acl-attachment"),
                           ("exos", "ntp-server"), ("exos", "ntp"), ("exos", "sntp-server"),
                           ("exos", "syslog-target"), ("exos", "dns-server"), ("exos", "dns-suffix"),
                           ("exos", "system-name"),
                           ("exos", "port-link"), ("exos", "jumbo-frame-size"), ("exos", "sharing"),
                           ("exos", "stpd"), ("exos", "stpd-port"), ("exos", "elrp"),
                           ("exos", "mlag-peer"), ("exos", "mlag-port"),
                           ("fortiadc", "load-balance pool/pool_member"),
                           ("fortiadc", "system certificate local_cert_group/group_member"),
                           ("fortiadc", "load-balance virtual-server"), ("fortiadc", "load-balance real-server"),
                           ("nxos", "interface"), ("nxos", "vlan-membership"), ("nxos", "vlan"),
                           ("nxos", "static-route"), ("nxos", "l3-interface"), ("nxos", "dhcp-relay"),
                           ("nxos", "port-bounce"), ("nxos", "port-channel"), ("nxos", "port-channel-member"),
                           ("nxos", "vpc-port"), ("nxos", "vpc-peer-link"), ("nxos", "vpc-domain"),
                           ("nxos", "ip-access-list"), ("nxos", "interface-access-group"),
                           ("nxos", "ntp-server"), ("nxos", "ntp-source"), ("nxos", "syslog-server"),
                           ("nxos", "syslog-source"), ("nxos", "dns-server"), ("nxos", "dns-domain"),
                           ("nxos", "startup-config"),
                           ("junos", "interface"), ("junos", "vlan-membership"), ("junos", "vlan"),
                           ("junos", "system"), ("junos", "ntp-server"), ("junos", "syslog-host"),
                           ("junos", "static-route"), ("junos", "irb"), ("junos", "vrrp"),
                           ("junos", "poe"), ("junos", "inline-power"), ("junos", "port-bounce"),
                           ("junos", "lag"), ("junos", "rstp"), ("junos", "rstp-interface"),
                           ("junos", "ospf-interface"), ("junos", "ospf3-interface"), ("junos", "prefix-list"),
                           ("junos", "route-policy"), ("junos", "bgp-group"), ("junos", "bgp-neighbor"),
                           ("junos", "firewall-filter"), ("junos", "filter-binding"),
                           ("junos", "security-zone"), ("junos", "address-book-address"),
                           ("junos", "address-book-set"), ("junos", "security-policy"),
                           ("junos", "nat-source-rule"), ("junos", "nat-destination-pool"),
                           ("junos", "nat-destination-rule"),
                           ("junos", "dhcp-pool"), ("junos", "dhcp-reservation"), ("junos", "dhcp-relay-server"),
                           ("junos", "dhcp-relay-group"),
                           ("fortios", "system interface"), ("fortios", "router static"),
                           ("fortios", "switch-controller managed-switch/ports"), ("fortios", "port-bounce"),
                           ("fortios", "poe-cycle")}
    assert loaded[("fortiadc", "load-balance pool/pool_member")].versions == ("7.6.7 build0676",)
    assert loaded[("fortiadc", "load-balance pool/pool_member")].exact_versions
    assert loaded[("exos", "ports")].implicit_keys and loaded[("exos", "ports")].ops == ("update",)
    assert loaded[("fortios", "firewall address")].versions == ("8.0.0 build0167", "7.6.8 build3744", "7.6.7 build3704", "8.0.2 build0251")
    assert loaded[("fortios", "firewall policy")].versions == ("7.6.8 build3744", "8.0.2 build0251")
    assert loaded[("fortios", "firewall service custom")].versions == ("7.6.8 build3744", "8.0.2 build0251")
    assert not loaded[("fortios", "firewall service custom")].provisional
    assert loaded[("fortios", "firewall service custom")].measured
    assert loaded[("fortios", "firewall addrgrp")].versions == ("8.0.0 build0167", "7.6.8 build3744", "7.6.7 build3704")
    assert loaded[("fortios", "system dhcp server/reserved-address")].versions == ("8.0.0 build0167", "7.6.8 build3744", "7.6.7 build3704")
    assert loaded[("exos", "vlan")].versions == ("33.7.1.6", "33.6.1.14")
    assert loaded[("fortios", "port-bounce")].action == "port-bounce"
    assert loaded[("fortios", "poe-cycle")].action == "poe-cycle"
    assert set(loaded[("fortios", "switch-controller managed-switch/ports")].attributes) == {
        "description", "status", "vlan", "allowed-vlans", "untagged-vlans", "allowed-vlans-all", "poe-status",
    }
    assert loaded[("exos", "inline-power")].action is None
    assert loaded[("exos", "port-bounce")].action == "port-bounce"
    assert set(loaded[("exos", "ports")].attributes) == {"display-string", "description-string", "admin-state"}
    assert loaded[("eos", "interface")].versions == ("4.36.1F",) and loaded[("eos", "interface")].exact_versions
    # 1.0.12 G123 (E06/E23): speed, MTU and PoE of an EOS port; bounce and PoE cycle have their own tables
    assert set(loaded[("eos", "interface")].attributes) == {"description", "admin-state", "speed", "mtu", "poe"}
    assert loaded[("eos", "port-bounce")].action == "port-bounce"
    assert loaded[("eos", "inline-power")].action == "poe-cycle"
    assert loaded[("eos", "vlan-membership")].ops == ("update",)
    assert set(loaded[("eos", "vlan-membership")].attributes) == {"access-vlan", "mode", "allowed-vlans", "native-vlan",
                                                                  "voice-vlan", "dot1x", "mab"}
    assert loaded[("eos", "vlan")].ops == ("create", "update", "delete") and loaded[("eos", "vlan")].exact_versions
    assert loaded[("nxos", "interface")].versions == ("9.3(12)",) and loaded[("nxos", "interface")].exact_versions
    assert set(loaded[("nxos", "interface")].attributes) == {"description", "admin-state"}
    assert loaded[("nxos", "vlan-membership")].ops == ("update",)
    assert loaded[("ios", "interface")].versions == ("15.9(3)M12", "15.2(20200924:215240)")
    assert loaded[("ios", "vlan-membership")].versions == ("15.2(20200924:215240)",)
    assert loaded[("iosxe", "interface")].versions == ("17.18.2",) == loaded[("iosxe", "vlan-membership")].versions
    assert all(loaded[(platform, table)].exact_versions for platform in ("ios", "iosxe")
               for table in ("interface", "vlan-membership"))
    assert loaded[("junos", "interface")].versions == ("26.2R1.7",) and loaded[("junos", "interface")].exact_versions
    assert loaded[("junos", "interface")].implicit_keys and loaded[("junos", "vlan-membership")].implicit_keys
    assert set(loaded[("junos", "interface")].attributes) == {"description", "admin-state", "speed", "auto-negotiation", "mtu"}
    assert loaded[("junos", "vlan-membership")].attributes["access-vlan"].default == "default"


def shipped():
    from importlib import resources
    path = resources.files("netops_admin") / "profiles" / "fortios-firewall-address.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_shipped_profile_texts_name_no_internal_documents_or_accounts():
    from importlib import resources
    directory = resources.files("netops_admin") / "profiles"
    names = sorted(entry.name for entry in directory.iterdir() if entry.name.endswith(".json"))
    assert len(names) == 178
    for name in names:
        text = (directory / name).read_text(encoding="utf-8")
        for marker in ("docs/t167", "not releasable", "netops-test-", " branch "):
            assert marker not in text, (name, marker)


@pytest.mark.parametrize(("mutate", "fragment"), [
    (lambda data: data.update(extra=1), "profile fields differ"),
    (lambda data: data.update(versions=[]), "at least one tested version"),
    (lambda data: data.update(ops=["create", "replace"]), "ops must be a subset"),
    (lambda data: data.update(key_pattern="[a-z]+"), "must be anchored"),
    (lambda data: data.update(key_pattern="^([$"), "does not compile"),
    (lambda data: data["attributes"]["comment"].update(type="blob"), "unknown type"),
    (lambda data: data["attributes"]["comment"].pop("max_length"), "needs max_length"),
    (lambda data: data["attributes"]["comment"].update(shell=True), "unknown fields"),
    (lambda data: data["attributes"]["subnet"].update(required_on_create=True, unset=True),
     "both required and unsettable"),
    (lambda data: data.update(volatile=["uuid", "comment"]), "listed twice"),
    (lambda data: data.update(inverse_identity_changes={"delete": ["subnet"]}), "must be a volatile"),
    (lambda data: data.update(reserved_values={"color": ["1"]}), "unknown attribute"),
    (lambda data: data.update(rollback_evidence=""), "measured rollback"),
    (lambda data: data.update(platform="vyos"), "unknown platform"),
])
def test_profile_validation_is_strict(mutate, fragment):
    data = copy.deepcopy(shipped())
    mutate(data)
    with pytest.raises(profiles.ProfileError) as caught:
        profiles.parse_profile(data)
    assert fragment in str(caught.value)


@pytest.mark.parametrize("request_id", ["request1\n", "request1\r", "short", "r" * 65, None])
def test_store_request_refuses_an_invalid_id_before_read(tmp_path, monkeypatch, request_id):
    store = Store(tmp_path / "state")

    def unexpected_read(*args):
        raise AssertionError("invalid request ID reached document lookup")

    monkeypatch.setattr(store, "_document", unexpected_read)
    assert store.request(request_id) is None


@pytest.mark.parametrize("request_id", ["request1", "Req_.:-1", "r" * 64])
def test_store_request_preserves_a_valid_id_and_fingerprint(tmp_path, request_id):
    request = parse_request(request_bytes(device="fw-1", request_id=request_id))
    fingerprint = request.fingerprint()
    store = Store(tmp_path / "state")
    store.remember_request(request_id, "a" * 32, fingerprint, "fw-1")
    assert store.request(request_id) == {
        "request_id": request_id,
        "change_id": "a" * 32,
        "request_sha256": fingerprint,
        "device": "fw-1",
    }
    assert parse_request(request_bytes(device="fw-1", request_id=request_id)).fingerprint() == fingerprint
