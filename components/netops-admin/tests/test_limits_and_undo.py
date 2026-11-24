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
from approved_apply import approved_apply


def limited(**changes):
    limits = dict(DEFAULT_LIMITS)
    limits.update(changes)
    return limits


def test_changes_per_device_per_hour_are_bounded(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device, limits=limited(changes_per_device_per_hour=1))
    assert approved_apply(runtime, "lab", request())["result"] == "confirmed"
    with pytest.raises(BudgetExhausted) as caught:
        approved_apply(runtime, "lab", request(key="second-host", request_id="req-second-1"))
    assert "this device for this hour" in caught.value.reasons[0]
    assert "second-host" not in device.addresses
    assert approved_apply(runtime, "lab", request())["result"] == "confirmed"


def test_changes_per_day_are_bounded(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS(), limits=limited(changes_per_day=1))
    approved_apply(runtime, "lab", request())
    with pytest.raises(BudgetExhausted) as caught:
        approved_apply(runtime, "lab", request(key="second-host", request_id="req-second-1"))
    assert "for this day" in caught.value.reasons[0]


def test_rejected_requests_have_their_own_budget(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device, limits=limited(rejections_per_hour=2))
    for number in range(2):
        # "all" is refused by the plan itself, before the (well-formed) plan hash is compared
        with pytest.raises(Rejected) as caught:
            execute.apply(runtime, "lab", request(key="all", request_id="req-bad-%04d" % number),
                          expected_plan_sha256="0" * 64)
        assert not isinstance(caught.value, BudgetExhausted)
    with pytest.raises(BudgetExhausted) as caught:
        approved_apply(runtime, "lab", request())
    assert "rejected requests" in caught.value.reasons[0]
    assert "new-host" not in device.addresses


def test_journal_capacity_blocks_new_changes(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS(), limits=limited(journal_records=1))
    approved_apply(runtime, "lab", request())
    with pytest.raises(BudgetExhausted) as caught:
        approved_apply(runtime, "lab", request(key="second-host", request_id="req-second-1"))
    assert "maximum number of operations" in caught.value.reasons[0]


def test_plan_size_is_bounded(tmp_path):
    device = FakeFortiOS()
    with pytest.raises(Rejected) as caught:
        approved_apply(make_runtime(tmp_path, device, limits=limited(plan_commands=2)), "lab", request())
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
    first = approved_apply(runtime, "lab", request(op=op, key=key, changes=changes))
    assert first["result"] == "confirmed"
    back = execute.undo(runtime, first["change_id"], "investigated")
    assert back["result"] == "confirmed" and back["request_id"] == "undo-%s" % first["change_id"]
    assert check(device)
    again = execute.undo(runtime, first["change_id"], "investigated")
    assert again["change_id"] == back["change_id"]


def test_undo_refuses_an_object_changed_since(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    device.addresses["spare-host"]["comment"] = "someone else"
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, first["change_id"], "investigated")
    assert "differs from the state" in caught.value.reasons[0]
    assert len(device.applied_blocks) == blocks


def test_undo_of_a_delete_refuses_a_recreated_object(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="delete", key="spare-host", changes={}))
    device.addresses["spare-host"] = {"uuid": "x", "subnet": "192.0.2.99 255.255.255.255"}
    with pytest.raises(Rejected):
        execute.undo(runtime, first["change_id"], "investigated")


def test_only_a_confirmed_operation_can_be_undone(tmp_path):
    device = FakeFortiOS()
    device.drop_comment = True
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "x y"}))
    assert first["result"] == "reverted"
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, first["change_id"], "investigated")
    assert "only a confirmed operation" in caught.value.reasons[0]
    with pytest.raises(Rejected):
        execute.undo(runtime, "0" * 32, "investigated")


def test_undo_on_exos_restores_the_description(tmp_path):
    device = FakeExos()
    runtime = make_exos_runtime(tmp_path, device)
    first = approved_apply(runtime, "sw", exos_request(op="update", key="spare", changes={"description": "parked"}))
    back = execute.undo(runtime, first["change_id"], "investigated")
    assert back["result"] == "confirmed"
    assert device.vlans["spare"]["description"] == "unused" and device.saves == 2


UNDO_DONE = ("undo of this change has already been performed; "
             "after a reverted change remove the object with regular administration")


def test_second_undo_with_other_reason_says_the_undo_was_already_performed(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    assert execute.undo(runtime, first["change_id"], "investigated")["result"] == "confirmed"
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, first["change_id"], "another reason")
    assert caught.value.reasons == [UNDO_DONE]
    assert len(device.applied_blocks) == blocks


def test_reused_request_id_of_a_regular_request_keeps_the_original_message(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    taken = "undo-%s" % first["change_id"]
    approved_apply(runtime, "lab", request(request_id=taken))
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, "lab", request(request_id=taken, changes={"subnet": "192.0.2.31/32", "comment": "x"}))
    assert caught.value.reasons == [execute.REUSED_REQUEST]


# 109-16: undo preview (execute.preview_undo), read only


def _footprint(tmp_path, runtime, device):
    audit = tmp_path / "audit" / "audit.jsonl"
    return (len(device.applied_blocks), [r["change_id"] for r in runtime.store.records()],
            audit.read_text() if audit.exists() else "", sorted(device.stitches), sorted(device.triggers))


def test_undo_preview_of_a_confirmed_update_is_ready_with_swapped_states(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    assert first["result"] == "confirmed"
    ahead = execute.preview_undo(runtime, first["change_id"], "investigated")
    assert ahead["result"] == "ready" and ahead["reasons"] == [] and ahead["reason_codes"] == []
    assert ahead["undo_of"] == first["change_id"] and ahead["request_id"] == "undo-%s" % first["change_id"]
    assert ahead["op"] == "update" and ahead["key"] == "spare-host" and ahead["commands"]
    assert ahead["predicted"]["before"] == first["plan"]["predicted"]["after"]
    assert ahead["predicted"]["after"] == first["plan"]["predicted"]["before"]
    back = execute.undo(runtime, first["change_id"], "investigated")
    assert back["result"] == "confirmed" and back["plan"]["plan_sha256"] == ahead["plan_sha256"]


def test_undo_preview_refuses_an_object_changed_since(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    device.addresses["spare-host"]["comment"] = "someone else"
    before = _footprint(tmp_path, runtime, device)
    refused = runtime.store.rejections_since(runtime.store.budget_now() - execute.HOUR)
    ahead = execute.preview_undo(runtime, first["change_id"], "investigated")
    assert ahead["result"] == "rejected" and ahead["undo_of"] == first["change_id"]
    assert any("differs from the state" in reason for reason in ahead["reasons"])
    assert _footprint(tmp_path, runtime, device) == before
    assert runtime.store.rejections_since(runtime.store.budget_now() - execute.HOUR) == refused + 1


def test_undo_preview_needs_a_confirmed_operation(tmp_path):
    device = FakeFortiOS()
    device.drop_comment = True
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "x y"}))
    assert first["result"] == "reverted"
    with pytest.raises(Rejected) as caught:
        execute.preview_undo(runtime, first["change_id"], "investigated")
    assert "only a confirmed operation" in caught.value.reasons[0]
    with pytest.raises(Rejected) as caught:
        execute.preview_undo(runtime, "0" * 32, "investigated")
    assert "only a confirmed operation" in caught.value.reasons[0]


def test_undo_preview_after_the_undo_is_undo_already_done_without_a_write(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    back = execute.undo(runtime, first["change_id"], "investigated")
    assert back["result"] == "confirmed"
    before = _footprint(tmp_path, runtime, device)
    for reason in ("investigated", "another reason"):
        with pytest.raises(Rejected) as caught:
            execute.preview_undo(runtime, first["change_id"], reason)
        assert caught.value.reasons == [UNDO_DONE] and caught.value.reason_codes == ["undo_already_done"]
    assert _footprint(tmp_path, runtime, device) == before


def test_undo_preview_after_the_undo_counts_against_the_rejection_budget(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device, limits=limited(rejections_per_hour=2))
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    assert execute.undo(runtime, first["change_id"], "investigated")["result"] == "confirmed"
    assert runtime.store.rejections_since(runtime.store.budget_now() - execute.HOUR) == 0
    before = _footprint(tmp_path, runtime, device)
    for _ in range(2):
        # the same reason makes the identical undo request: _preview answers known-request
        with pytest.raises(Rejected) as caught:
            execute.preview_undo(runtime, first["change_id"], "investigated")
        assert caught.value.reason_codes == ["undo_already_done"]
        assert not isinstance(caught.value, BudgetExhausted)
    assert runtime.store.rejections_since(runtime.store.budget_now() - execute.HOUR) == 2
    assert _footprint(tmp_path, runtime, device) == before
    with pytest.raises(BudgetExhausted) as caught:
        approved_apply(runtime, "lab", request(request_id="req-after-undo-preview"))
    assert "rejected requests" in caught.value.reasons[0]
    assert "new-host" not in device.addresses


def test_undo_preview_writes_nothing_to_device_journal_or_notification(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "mine"}))
    sent = []
    runtime.notifier = lambda record: sent.append(record) or "sent"
    before = _footprint(tmp_path, runtime, device)
    ahead = execute.preview_undo(runtime, first["change_id"], "investigated")
    assert ahead["result"] == "ready"
    assert _footprint(tmp_path, runtime, device) == before
    assert runtime.store.request("undo-%s" % first["change_id"]) is None
    assert device.addresses["spare-host"]["comment"] == "mine"
    assert sent == []
    assert runtime.store.operation(first["change_id"])["result"] == "confirmed"


def test_undo_preview_on_exos(tmp_path):
    device = FakeExos()
    runtime = make_exos_runtime(tmp_path, device)
    first = approved_apply(runtime, "sw", exos_request(op="update", key="spare", changes={"description": "parked"}))
    saves = device.saves
    ahead = execute.preview_undo(runtime, first["change_id"], "investigated")
    assert ahead["result"] == "ready" and ahead["device"] == "sw"
    assert device.vlans["spare"]["description"] == "parked" and device.saves == saves


def test_undo_preview_of_a_schema_transaction(tmp_path, monkeypatch):
    import copy

    from test_schema_execute import runtime as schema_runtime
    from test_schema_plan import op
    from test_schema_runtime import request as schema_request

    value, fake = schema_runtime(tmp_path, monkeypatch)
    result = approved_apply(value, "lab", schema_request([op(changes={"comment": "intermediate"}),
                                                         op(changes={"comment": "final"})]))
    assert result["result"] == "confirmed"
    addresses, writes, records = copy.deepcopy(fake.addresses), len(fake.applied_blocks), len(value.store.records())
    ahead = execute.preview_undo(value, result["change_id"], "operator undo")
    assert ahead["result"] == "ready", ahead["reasons"]
    assert ahead["undo_of"] == result["change_id"] and ahead["request_id"] == "undo-%s" % result["change_id"]
    assert fake.addresses == addresses and len(fake.applied_blocks) == writes
    assert len(value.store.records()) == records
    undone = execute.undo(value, result["change_id"], "operator undo")
    assert undone["result"] == "confirmed"
    with pytest.raises(Rejected) as caught:
        execute.preview_undo(value, result["change_id"], "operator undo")
    assert caught.value.reason_codes == ["undo_already_done"]
