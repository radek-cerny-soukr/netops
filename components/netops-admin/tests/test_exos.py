from __future__ import annotations

import pytest
from conftest import request_bytes

from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIRMWARE = "33.7.1.6"


def plan(snapshot, firmware=FIRMWARE, **fields):
    fields.setdefault("table", "vlan")
    fields.setdefault("key", "guest")
    fields.setdefault("changes", {"tag": 3000})
    return build_plan("exos", snapshot, parse_request(request_bytes(**fields)), firmware=firmware)


def rejected(snapshot, fragment, **fields):
    with pytest.raises(Rejected) as caught:
        plan(snapshot, **fields)
    assert any(fragment in reason for reason in caught.value.reasons), caught.value.reasons


def replace(snapshot: bytes, old: str, new: str) -> bytes:
    text = snapshot.decode("utf-8")
    assert text.count(old) == 1
    return text.replace(old, new).encode("utf-8")


def test_create_plan(exos_snapshot):
    document = plan(exos_snapshot, changes={"tag": 3000, "description": "guest wifi"})
    assert document["commands"] == [
        "create vlan guest tag 3000",
        'configure vlan guest description "guest wifi"',
    ]
    assert document["inverse"] == ["delete vlan guest"]
    assert document["predicted"]["after"] == {"description": "guest wifi", "tag": "3000"}


def test_create_prediction_matches_the_device_format(exos_snapshot):
    document = plan(exos_snapshot, changes={"tag": 3000, "description": "guest wifi"})
    after = replace(exos_snapshot, 'create vlan "notag"\n',
                    'create vlan "guest"\nconfigure vlan guest description "guest wifi" \n'
                    'configure vlan guest tag 3000\ncreate vlan "notag"\n')
    assert verify(document, after)["result"] == "match"
    assert verify(document, exos_snapshot, expect="before")["result"] == "match"


def test_update_description_and_its_inverse(exos_snapshot):
    document = plan(exos_snapshot, op="update", key="spare", changes={"description": "parked"})
    assert document["commands"] == ['configure vlan spare description "parked"']
    assert document["inverse"] == ['configure vlan spare description "unused"']
    removal = plan(exos_snapshot, op="update", key="spare", changes={"description": None})
    assert removal["commands"] == ["unconfigure vlan spare description"]
    assert removal["inverse"] == ['configure vlan spare description "unused"']
    adding = plan(exos_snapshot, op="update", key="voice", changes={"description": "phones"})
    assert adding["inverse"] == ["unconfigure vlan voice description"]


def test_description_of_a_vlan_with_ports_may_change(exos_snapshot):
    assert plan(exos_snapshot, op="update", key="DATA", changes={"description": "users"})["commands"]


def test_delete_plan_and_recreation(exos_snapshot):
    document = plan(exos_snapshot, op="delete", key="spare", changes={})
    assert document["commands"] == ["delete vlan spare"]
    assert document["inverse"] == ["create vlan spare tag 3990", 'configure vlan spare description "unused"']
    assert document["predicted"]["before"] == {"description": "unused", "tag": "3990"}


def test_verify_detects_a_change_elsewhere(exos_snapshot):
    document = plan(exos_snapshot, op="delete", key="spare", changes={})
    removed = replace(exos_snapshot, 'create vlan "spare"\nconfigure vlan spare description "unused"\n'
                                     "configure vlan spare tag 3990\n", "")
    assert verify(document, removed)["result"] == "match"
    tampered = replace(removed, "configure ports 1 display-string uplink", "configure ports 1 display-string x")
    assert verify(document, tampered)["differences"] == ["configuration outside the planned object changed"]


@pytest.mark.parametrize(("fields", "fragment"), [
    ({"changes": {"tag": 10}}, "already used by another VLAN"),
    ({"changes": {"tag": 1}}, "must lie in 2..4095"),
    ({"changes": {"tag": 4095}}, "reserved"),
    ({"changes": {"tag": 4096}}, "must lie in 2..4095"),
    ({"changes": {"tag": True}}, "string, an integer or null"),
    ({"changes": {"description": "x"}}, "create needs tag"),
    ({"changes": {"tag": 3000, "description": "none"}}, "CLI keyword"),
    ({"changes": {"tag": 3000, "description": "y" * 65}}, "longer than 64"),
    ({"key": "Default", "changes": {"tag": 3000}}, "is protected"),
    ({"key": "mgmt", "op": "delete", "changes": {}}, "is protected"),
    ({"key": "data", "changes": {"tag": 3000}}, "letter case"),
    ({"key": "uplink", "changes": {"tag": 3000}}, "already used"),
    ({"key": "1guest"}, "does not match"),
    ({"key": "g" * 33}, "does not match"),
    ({"op": "delete", "key": "DATA", "changes": {}}, "is referenced"),
    ({"op": "delete", "key": "voice", "changes": {}}, "is referenced"),
    ({"op": "delete", "key": "notag", "changes": {}}, "cannot be recreated"),
    ({"op": "update", "key": "spare", "changes": {"tag": 3001}}, "cannot be updated"),
])
def test_rejections(exos_snapshot, fields, fragment):
    rejected(exos_snapshot, fragment, **fields)


def test_firmware_is_required_and_must_be_measured(exos_snapshot):
    rejected(exos_snapshot, "must state it", firmware=None)
    rejected(exos_snapshot, "not measured on firmware", firmware="33.7.2")


def test_snapshot_without_vlan_module_is_refused(exos_snapshot):
    rejected(replace(exos_snapshot, "# Module vlan configuration.", "# Module other configuration."),
             "no vlan module")


def test_repeated_attribute_line_makes_the_vlan_unsupported(exos_snapshot):
    doubled = replace(exos_snapshot, "configure vlan spare tag 3990\n",
                      "configure vlan spare tag 3990\nconfigure vlan spare tag 3991\n")
    rejected(doubled, "outside the profile", op="delete", key="spare", changes={})


TIMERS = """Current Time: 2026-09-23 12:57:05
--------------------------------------------------------------------------------
UPM               Profile       Flags              Next Execution
Timer             Name                             time
--------------------------------------------------------------------------------
netops000000t    netops000000p  eo            2026-09-23 13:12:03
netops111111t    netops111111p  eo
--------------------------------------------------------------------------------
"""

PROFILE = """Created at : 2026-09-23 12:54:56

************Profile Contents Begin************
configure vlan spare description "unused"

************Profile Contents Ends*************

Profile State: Enabled
"""


def test_upm_listings_as_the_switch_prints_them():
    from netops_admin import exos

    assert exos.timer_row(TIMERS, "netops000000t") == {"profile": "netops000000p", "flags": "eo",
                                                      "next": "2026-09-23 13:12:03"}
    assert exos.timer_row(TIMERS, "netops111111t")["next"] is None
    assert exos.switch_field(exos.SWITCH_TIME, "Current Time:     Wed Sep  3 13:09:33 2026\n", "clock") \
        == "Wed Sep 3 13:09:33 2026"
    assert exos.profile_contents(PROFILE) == ['configure vlan spare description "unused"']
    assert exos.listed_names(TIMERS) == ["netops000000t", "netops111111t"]


def test_safeguard_names_fit_the_fixed_upm_columns():
    from netops_admin import exos

    names = exos.safeguard_names("0123456789abcdef" * 2)
    assert names == {"profile": "netops012345p", "timer": "netops012345t"}


def test_errors_are_read_from_the_answer_not_the_echo():
    from netops_admin import exos

    assert exos.cli_error('configure vlan spare description "%% Failed"\n') is None
    assert exos.cli_error("delete upm timer x\n              ^\n%% Invalid input detected at '^' marker.\n")
    assert exos.cli_error("create vlan guest tag 3999\n") is None


def test_safeguard_in_the_snapshot_is_not_part_of_the_vlan_or_the_rest(exos_snapshot):
    document = plan(exos_snapshot, op="update", key="spare", changes={"description": "parked"})
    with_safeguard = exos_snapshot.decode("utf-8") + (
        "#\n# Module upm configuration.\n#\ncreate upm profile netops012345p\n"
        'configure vlan spare description "unused"\n\n.\ncreate upm timer netops012345t\n'
        "configure upm timer netops012345t profile netops012345p\n"
    )
    after = with_safeguard.replace('configure vlan spare description "unused"\nconfigure vlan spare tag',
                                   'configure vlan spare description "parked"\nconfigure vlan spare tag')
    assert verify(document, after.encode("utf-8"))["result"] == "mismatch"
    document["safeguard_id"] = "012345"
    assert verify(document, after.encode("utf-8"))["result"] == "match"
    foreign = with_safeguard + "create upm profile other\nshow switch\n\n.\n"
    assert verify(document, foreign.encode("utf-8"), expect="before")["rest_matches"] is False
