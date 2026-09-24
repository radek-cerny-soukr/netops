from __future__ import annotations

import pytest
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request
from test_execute_exos import make_runtime as make_exos_runtime
from test_execute_exos import request as exos_request

from netops_admin import execute
from netops_admin.config import DEFAULT_LIMITS
from netops_admin.errors import BudgetExhausted, Rejected


def limited(**changes):
    limits = dict(DEFAULT_LIMITS)
    limits.update(changes)
    return limits


def test_changes_per_device_per_hour_are_bounded(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device, limits=limited(changes_per_device_per_hour=1))
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"
    with pytest.raises(BudgetExhausted) as caught:
        execute.apply(runtime, "lab", request(key="second-host", request_id="req-second-1"))
    assert "this device for this hour" in caught.value.reasons[0]
    assert "second-host" not in device.addresses
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"


def test_changes_per_day_are_bounded(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS(), limits=limited(changes_per_day=1))
    execute.apply(runtime, "lab", request())
    with pytest.raises(BudgetExhausted) as caught:
        execute.apply(runtime, "lab", request(key="second-host", request_id="req-second-1"))
    assert "for this day" in caught.value.reasons[0]


def test_rejected_requests_have_their_own_budget(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device, limits=limited(rejections_per_hour=2))
    for number in range(2):
        with pytest.raises(Rejected) as caught:
            execute.apply(runtime, "lab", request(key="all", request_id="req-bad-%04d" % number))
        assert not isinstance(caught.value, BudgetExhausted)
    with pytest.raises(BudgetExhausted) as caught:
        execute.apply(runtime, "lab", request())
    assert "rejected requests" in caught.value.reasons[0]
    assert "new-host" not in device.addresses


def test_journal_capacity_blocks_new_changes(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS(), limits=limited(journal_records=1))
    execute.apply(runtime, "lab", request())
    with pytest.raises(BudgetExhausted) as caught:
        execute.apply(runtime, "lab", request(key="second-host", request_id="req-second-1"))
    assert "maximum number of operations" in caught.value.reasons[0]


def test_plan_size_is_bounded(tmp_path):
    device = FakeFortiOS()
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device, limits=limited(plan_commands=2)), "lab", request())
    assert "more than 2 commands" in caught.value.reasons[0]
    assert device.applied_blocks == []


@pytest.mark.parametrize(("op", "key", "changes", "check"), [
    ("create", "new-host", {"subnet": "192.0.2.30/32", "comment": "new host"},
     lambda device: "new-host" not in device.addresses),
    ("update", "spare-host", {"comment": "changed"},
     lambda device: device.addresses["spare-host"]["comment"] == "unused"),
    ("update", "spare-host", {"comment": None},
     lambda device: device.addresses["spare-host"]["comment"] == "unused"),
    ("delete", "spare-host", {},
     lambda device: device.addresses["spare-host"]["subnet"] == "192.0.2.21 255.255.255.255"),
])
def test_undo_returns_a_confirmed_operation(tmp_path, op, key, changes, check):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = execute.apply(runtime, "lab", request(op=op, key=key, changes=changes))
    assert first["result"] == "confirmed"
    back = execute.undo(runtime, first["change_id"], "investigated")
    assert back["result"] == "confirmed" and back["request_id"] == "undo-%s" % first["change_id"]
    assert check(device)
    again = execute.undo(runtime, first["change_id"], "investigated")
    assert again["change_id"] == back["change_id"]


def test_undo_refuses_an_object_changed_since(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    device.addresses["spare-host"]["comment"] = "someone else"
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, first["change_id"], "investigated")
    assert "differs from the state" in caught.value.reasons[0]
    assert len(device.applied_blocks) == blocks


def test_undo_of_a_delete_refuses_a_recreated_object(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = execute.apply(runtime, "lab", request(op="delete", key="spare-host", changes={}))
    device.addresses["spare-host"] = {"uuid": "x", "subnet": "192.0.2.99 255.255.255.255"}
    with pytest.raises(Rejected):
        execute.undo(runtime, first["change_id"], "investigated")


def test_only_a_confirmed_operation_can_be_undone(tmp_path):
    device = FakeFortiOS()
    device.drop_comment = True
    runtime = make_runtime(tmp_path, device)
    first = execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "x y"}))
    assert first["result"] == "reverted"
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, first["change_id"], "investigated")
    assert "only a confirmed operation" in caught.value.reasons[0]
    with pytest.raises(Rejected):
        execute.undo(runtime, "0" * 32, "investigated")


def test_undo_on_exos_restores_the_description(tmp_path):
    device = FakeExos()
    runtime = make_exos_runtime(tmp_path, device)
    first = execute.apply(runtime, "sw", exos_request(op="update", key="spare", changes={"description": "parked"}))
    back = execute.undo(runtime, first["change_id"], "investigated")
    assert back["result"] == "confirmed"
    assert device.vlans["spare"]["description"] == "unused" and device.saves == 2
