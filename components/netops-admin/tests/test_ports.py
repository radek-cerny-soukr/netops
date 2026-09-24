from __future__ import annotations

import pytest
from conftest import request_bytes
from fake_exos import FakeExos
from test_execute_exos import make_runtime

from netops_admin import exos, execute
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIRMWARE = "33.7.1.6"


def port_request(key="10", changes=None, request_id="req-port-0001"):
    return parse_request(request_bytes(table="ports", op="update", key=key,
                                       changes={"display-string": "Cam-01"} if changes is None else changes,
                                       request_id=request_id))


def snapshot(device=None):
    return (device or FakeExos()).snapshot().encode("utf-8")


def test_plan_sets_and_restores_a_port_without_a_string():
    plan = build_plan("exos", snapshot(), port_request(), firmware=FIRMWARE)
    assert plan["commands"] == ["configure ports 10 display-string Cam-01"]
    assert plan["inverse"] == ["unconfigure ports 10 display-string"]
    assert plan["predicted"] == {"before": {}, "after": {"display-string": "Cam-01"}}


def test_plan_replaces_and_removes_an_existing_string():
    plan = build_plan("exos", snapshot(), port_request(key="11"), firmware=FIRMWARE)
    assert plan["inverse"] == ["configure ports 11 display-string Zyxel-5p"]
    removal = build_plan("exos", snapshot(), port_request(key="11", changes={"display-string": None}),
                         firmware=FIRMWARE)
    assert removal["commands"] == ["unconfigure ports 11 display-string"]
    assert removal["predicted"]["after"] == {}


@pytest.mark.parametrize("value", ["10", "two words", "A" * 16, "-dash"])
def test_display_string_values_the_switch_would_misread_are_refused(value):
    with pytest.raises(Rejected):
        build_plan("exos", snapshot(), port_request(changes={"display-string": value}), firmware=FIRMWARE)


def test_create_and_delete_are_not_offered_for_ports():
    for op in ("create", "delete"):
        with pytest.raises(Rejected):
            build_plan("exos", snapshot(), parse_request(request_bytes(
                table="ports", op=op, key="10", changes={} if op == "delete" else {"display-string": "x"})),
                firmware=FIRMWARE)


def test_rest_of_the_configuration_is_not_hidden_by_the_port_number():
    device = FakeExos()
    plan = build_plan("exos", snapshot(device), port_request(), firmware=FIRMWARE)
    device.port_strings["10"] = "Cam-01"
    assert verify(plan, snapshot(device))["result"] == "match"
    other_line = snapshot(device).decode("utf-8").replace("Default settings for the access port", "Changed by someone")
    assert verify(plan, other_line.encode("utf-8"))["rest_matches"] is False


def test_port_lists_are_refused():
    text = FakeExos().snapshot() + "configure ports 5-6 display-string Pair\n"
    with pytest.raises(Rejected) as caught:
        build_plan("exos", text.encode("utf-8"), port_request(), firmware=FIRMWARE)
    assert "port lists" in caught.value.reasons[0]


def test_port_answers_as_the_switch_prints_them():
    assert exos.shown_port("Port:\t10\n\tVirtual-router:\tVR-Default\n", "10") == {}
    assert exos.shown_port("Port:\t11(Zyxel-5p-hloupy):\n", "11") == {"display-string": "Zyxel-5p-hloupy"}
    assert exos.shown_port("%% Unrecognized command\n%% Invalid port number detected.\r\n", "17") is None
    with pytest.raises(Rejected):
        exos.shown_port("Port:\t12(Uplink-SW3):\n", "10")


def test_port_string_is_confirmed_checked_saved_and_undone(tmp_path):
    device = FakeExos()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "sw", port_request())
    assert record["result"] == "confirmed" and device.port_strings["10"] == "Cam-01"
    assert "check_identity_passed" in [step["step"] for step in record["steps"]] and device.saves == 1
    back = execute.undo(runtime, record["change_id"], "investigated")
    assert back["result"] == "confirmed" and "10" not in device.port_strings


def test_check_account_seeing_another_string_reverts(tmp_path):
    device = FakeExos()

    def hook(fake, steps):
        if len(fake.applied_blocks) == 2:
            fake.check_override = {"10": "Other"}

    device.on_apply = hook
    record = execute.apply(make_runtime(tmp_path, device), "sw", port_request())
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch"
    assert "10" not in device.port_strings
