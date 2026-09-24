from __future__ import annotations

import pytest
from conftest import request_bytes

from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected
from netops_admin.request import parse_request


def plan(snapshot, protected=None, firmware=None, **fields):
    return build_plan("fortios", snapshot, parse_request(request_bytes(**fields)),
                      firmware=firmware, protected=protected)


def rejected(snapshot, fragment, **fields):
    with pytest.raises(Rejected) as caught:
        plan(snapshot, **fields)
    assert any(fragment in reason for reason in caught.value.reasons), caught.value.reasons


def replace(snapshot: bytes, old: str, new: str) -> bytes:
    text = snapshot.decode("utf-8")
    assert text.count(old) == 1
    return text.replace(old, new).encode("utf-8")


NEW_ENTRY = (
    '    edit "new-host"\n'
    "        set uuid 00000000-0000-4000-8000-0000000000ff\n"
    '        set comment "added"\n'
    "        set subnet 192.0.2.30 255.255.255.255\n"
    "    next\n"
    "end\nconfig firewall addrgrp\n"
)


def test_create_plan_renders_commands_inverse_and_prediction(fortios_snapshot):
    document = plan(fortios_snapshot, changes={"subnet": "192.0.2.30 255.255.255.255", "comment": "added"})
    assert document["firmware"] == "8.0.0 build0167"
    assert document["commands"] == [
        "config firewall address",
        '    edit "new-host"',
        '        set comment "added"',
        "        set subnet 192.0.2.30 255.255.255.255",
        "    next",
        "end",
    ]
    assert document["inverse"] == ["config firewall address", '    delete "new-host"', "end"]
    assert document["predicted"] == {
        "before": None,
        "after": {"comment": "added", "subnet": "192.0.2.30 255.255.255.255"},
    }
    assert "new host" not in str(document)
    assert document["user_request_characters"] == len("create an address object for the new host")


def test_create_accepts_prefix_notation(fortios_snapshot):
    document = plan(fortios_snapshot, changes={"subnet": "198.51.100.64/26"})
    assert document["predicted"]["after"] == {"subnet": "198.51.100.64 255.255.255.192"}


def test_create_prediction_matches_a_device_snapshot(fortios_snapshot):
    document = plan(fortios_snapshot, changes={"subnet": "192.0.2.30/32", "comment": "added"})
    after = replace(fortios_snapshot, "end\nconfig firewall addrgrp\n", NEW_ENTRY)
    assert verify(document, after)["result"] == "match"
    assert verify(document, fortios_snapshot, expect="before")["result"] == "match"
    assert verify(document, fortios_snapshot)["result"] == "mismatch"


def test_verify_reports_a_wrong_value_and_a_foreign_change(fortios_snapshot):
    document = plan(fortios_snapshot, changes={"subnet": "192.0.2.30/32", "comment": "added"})
    wrong = replace(fortios_snapshot, "end\nconfig firewall addrgrp\n",
                    NEW_ENTRY.replace('"added"', '"other"'))
    result = verify(document, wrong)
    assert result["result"] == "mismatch"
    assert result["differences"] == ["comment: expected 'added', found 'other'"]
    foreign = replace(replace(fortios_snapshot, "end\nconfig firewall addrgrp\n", NEW_ENTRY),
                      'set comment "unused"', 'set comment "changed by someone"')
    assert verify(document, foreign)["differences"] == ["configuration outside the planned object changed"]


def test_update_plan_and_inverse_restore_previous_value(fortios_snapshot):
    document = plan(fortios_snapshot, op="update", key="spare-host", changes={"comment": "reserved"})
    assert document["commands"] == [
        "config firewall address", '    edit "spare-host"', '        set comment "reserved"', "    next", "end",
    ]
    assert document["inverse"] == [
        "config firewall address", '    edit "spare-host"', '        set comment "unused"', "    next", "end",
    ]
    assert document["predicted"]["before"] == {"comment": "unused", "subnet": "192.0.2.21 255.255.255.255"}
    assert document["predicted"]["after"]["comment"] == "reserved"


def test_update_removing_a_value_uses_unset_and_inverse_sets_it_back(fortios_snapshot):
    document = plan(fortios_snapshot, op="update", key="spare-host", changes={"comment": None})
    assert "        unset comment" in document["commands"]
    assert '        set comment "unused"' in document["inverse"]
    assert document["predicted"]["after"] == {"subnet": "192.0.2.21 255.255.255.255"}


def test_update_adding_a_value_has_an_unset_inverse(fortios_snapshot):
    document = plan(fortios_snapshot, op="update", key="lab-net", changes={"comment": "lab"})
    assert "        unset comment" in document["inverse"]


def test_update_of_referenced_object_allows_comment_but_not_subnet(fortios_snapshot):
    assert plan(fortios_snapshot, op="update", key="srv-web", changes={"comment": "front"})["commands"]
    rejected(fortios_snapshot, "cannot change on a referenced object",
             op="update", key="srv-web", changes={"subnet": "192.0.2.40/32"})
    rejected(fortios_snapshot, "cannot change on a referenced object",
             op="update", key="grouped-host", changes={"subnet": "192.0.2.40/32"})


def test_delete_plan_recreates_the_object_without_its_identity(fortios_snapshot):
    document = plan(fortios_snapshot, op="delete", key="spare-host", changes={})
    assert document["commands"] == ["config firewall address", '    delete "spare-host"', "end"]
    assert document["inverse"] == [
        "config firewall address", '    edit "spare-host"', '        set comment "unused"',
        "        set subnet 192.0.2.21 255.255.255.255", "    next", "end",
    ]
    assert document["inverse_identity_changes"] == ["uuid"]
    assert document["predicted"]["after"] is None


def test_delete_inverse_verifies_despite_a_new_uuid(fortios_snapshot):
    document = plan(fortios_snapshot, op="delete", key="spare-host", changes={})
    recreated = replace(fortios_snapshot, "00000000-0000-4000-8000-000000000004",
                        "00000000-0000-4000-8000-0000000000ee")
    assert verify(document, recreated, expect="before")["result"] == "match"


@pytest.mark.parametrize(("fields", "fragment"), [
    ({"op": "delete", "key": "srv-web", "changes": {}}, "is referenced"),
    ({"op": "delete", "key": "grouped-host", "changes": {}}, "is referenced"),
    ({"op": "delete", "key": "docs-fqdn", "changes": {}}, "outside the profile"),
    ({"op": "update", "key": "colored-host", "changes": {"comment": "x"}}, "outside the profile"),
    ({"op": "delete", "key": "all", "changes": {}}, "is protected"),
    ({"op": "delete", "key": "missing", "changes": {}}, "does not exist"),
    ({"op": "delete", "key": "spare-host", "changes": {"comment": "x"}}, "takes no attribute changes"),
    ({"op": "update", "key": "spare-host", "changes": {"comment": "unused"}}, "changes nothing"),
    ({"op": "update", "key": "spare-host", "changes": {}}, "names no attribute"),
    ({"op": "update", "key": "spare-host", "changes": {"subnet": None}}, "cannot be removed"),
    ({"key": "srv-web"}, "already used"),
    ({"key": "servers"}, "already used"),
    ({"key": "SPARE-HOST"}, "letter case"),
    ({"key": "web-in"}, "already used"),
    ({"changes": {"comment": "no subnet"}}, "create needs subnet"),
    ({"changes": {"subnet": "192.0.2.30/24"}}, "without host bits"),
    ({"changes": {"subnet": "192.0.2.300/32"}}, "without host bits"),
    ({"changes": {"subnet": "192.0.2.30/32", "color": 3}}, "not in the profile"),
    ({"changes": {"subnet": "192.0.2.30/32", "comment": "x" * 256}}, "longer than 255"),
    ({"changes": {"subnet": "192.0.2.30/32", "comment": 'say "hi"'}}, "printable ASCII only"),
    ({"changes": {"subnet": "192.0.2.30/32", "comment": "line\nbreak"}}, "printable ASCII only"),
    ({"changes": {"subnet": "192.0.2.30/32", "comment": "back\\slash"}}, "printable ASCII only"),
    ({"changes": {"subnet": "192.0.2.30/32", "comment": "café"}}, "printable ASCII only"),
    ({"changes": {"subnet": "192.0.2.30/32", "comment": ""}}, "use null"),
    ({"key": "bad name"}, "does not match"),
    ({"key": "x" * 80}, "does not match"),
    ({"table": "firewall policy"}, "no profile"),
])
def test_rejections(fortios_snapshot, fields, fragment):
    rejected(fortios_snapshot, fragment, **fields)


def test_policy_protects_additional_objects(fortios_snapshot):
    with pytest.raises(Rejected) as caught:
        plan(fortios_snapshot, protected={"firewall address": ["spare-host"]},
             op="delete", key="spare-host", changes={})
    assert caught.value.reasons == ["object 'spare-host' is protected"]


@pytest.mark.parametrize(("old", "new", "fragment"), [
    ("FGT80F-8.0.0-FW-build0167", "FGT80F-8.0.1-FW-build0245", "not measured on firmware"),
    ("FGT80F-8.0.0-FW-build0167", "FGT80F-8.0.0-FW-build0168", "not measured on firmware"),
    ("#config-version=", "#config-versio=", "header is missing"),
    (":vdom=0:", ":vdom=1:", "VDOMs enabled"),
    ("config firewall address\n", "config firewall address6\n", "no firewall address section"),
    ("    next\nend\nconfig firewall policy", "    next\nconfig firewall policy", "does not parse"),
])
def test_snapshot_rejections(fortios_snapshot, old, new, fragment):
    rejected(replace(fortios_snapshot, old, new), fragment)


def test_expected_firmware_must_match_the_snapshot(fortios_snapshot):
    with pytest.raises(Rejected) as caught:
        plan(fortios_snapshot, firmware="8.0.1 build0245")
    assert "differs from the expected" in caught.value.reasons[0]


def test_verify_refuses_a_tampered_plan(fortios_snapshot):
    document = plan(fortios_snapshot)
    document["commands"] = document["commands"] + ["execute reboot"]
    with pytest.raises(Rejected) as caught:
        verify(document, fortios_snapshot)
    assert "plan_sha256" in caught.value.reasons[0]


def test_verify_refuses_another_firmware(fortios_snapshot):
    document = plan(fortios_snapshot)
    other = replace(fortios_snapshot, "8.0.0-FW-build0167", "8.0.1-FW-build0245")
    with pytest.raises(Rejected):
        verify(document, other)
