from __future__ import annotations

import copy
import json

import pytest
from conftest import request_bytes

from netops_admin import profiles
from netops_admin.errors import Rejected
from netops_admin.request import MAX_REQUEST_BYTES, parse_request


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
                           ("fortios", "firewall addrgrp"), ("fortios", "system dhcp server/reserved-address"),
                           ("exos", "vlan-membership")}
    assert loaded[("exos", "ports")].implicit_keys and loaded[("exos", "ports")].ops == ("update",)
    assert loaded[("fortios", "firewall address")].versions == ("8.0.0 build0167", "7.6.7 build3704")
    assert loaded[("exos", "vlan")].versions == ("33.7.1.6",)


def shipped():
    from importlib import resources
    path = resources.files("netops_admin") / "profiles" / "fortios-firewall-address.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(("mutate", "fragment"), [
    (lambda data: data.update(extra=1), "profile fields differ"),
    (lambda data: data.update(versions=[]), "at least one measured version"),
    (lambda data: data.update(ops=["create", "replace"]), "ops must be a subset"),
    (lambda data: data.update(key_pattern="[a-z]+"), "must be anchored"),
    (lambda data: data.update(key_pattern="^([$"), "does not compile"),
    (lambda data: data["attributes"]["comment"].update(type="blob"), "unknown type"),
    (lambda data: data["attributes"]["comment"].pop("max_length"), "needs max_length"),
    (lambda data: data["attributes"]["comment"].update(shell=True), "unknown fields"),
    (lambda data: data["attributes"]["subnet"].update(unset=True), "both required and unsettable"),
    (lambda data: data.update(volatile=["uuid", "comment"]), "listed twice"),
    (lambda data: data.update(inverse_identity_changes={"delete": ["subnet"]}), "must be a volatile"),
    (lambda data: data.update(reserved_values={"color": ["1"]}), "unknown attribute"),
    (lambda data: data.update(rollback_evidence=""), "measured rollback"),
    (lambda data: data.update(platform="junos"), "unknown platform"),
])
def test_profile_validation_is_strict(mutate, fragment):
    data = copy.deepcopy(shipped())
    mutate(data)
    with pytest.raises(profiles.ProfileError) as caught:
        profiles.parse_profile(data)
    assert fragment in str(caught.value)
