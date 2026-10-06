from __future__ import annotations

import json

import pytest
from conftest import request_bytes
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime as fortios_runtime
from test_execute import request as fortios_request
from test_execute_exos import make_runtime as exos_runtime
from test_execute_exos import request as exos_request

from netops_admin import engine, execute
from netops_admin.errors import Rejected
from netops_admin.request import parse_request


def after_change(device, distort):
    device.distorted = False
    original = device.snapshot

    def snapshot():
        text = original()
        if device.distorted is None:
            device.distorted = True
            return distort(text)
        return text

    def hook(fake, lines):
        if len(fake.applied_blocks) == 2:
            fake.distorted = None

    device.snapshot = snapshot
    device.on_apply = hook
    return device


def wrapped_global(text):
    header, body = text.split("\n", 1)
    return header + "\nconfig global\n" + body + "end\n"


def wrapped_vdom(text):
    header, body = text.split("\n", 1)
    return header + "\nconfig vdom\nedit root\n" + body + "next\nend\n"


def cut_before_table(text):
    return text[:text.index("config firewall address")]


def cut_inside_table(text):
    return text[:text.index("config firewall address") + 60]


def cut_inside_quote(text):
    return text[:text.index('set comment "web"') + len('set comment "we')]


def without_header(text):
    return text.split("\n", 1)[1]


def vdoms_enabled(text):
    return text.replace(":vdom=0:", ":vdom=1:", 1)


def other_build(text):
    return text.replace("-FW-build0167-", "-FW-build0168-", 1)


def cut_before_vlan_module(text):
    return text[:text.index("# Module vlan configuration.")]


def result_events(tmp_path):
    lines = (tmp_path / "audit" / "audit.jsonl").read_text().splitlines()
    return [event for event in map(json.loads, lines) if event["event"] == "result"]


def check_reason(tmp_path, runtime, record, name, reason, blocked, detail=None):
    assert record["result"] == "reverted"
    assert record["reason"] == reason
    assert [step["detail"] for step in record["steps"] if step["step"] == "postcheck_failed"] == [detail or reason]
    assert runtime.store.operation(record["change_id"])["reason"] == reason
    assert [event["reason"] for event in result_events(tmp_path)][-1] == reason
    stored_block = runtime.store.blocked(name)
    if blocked:
        assert stored_block == {"device": name, "change_id": record["change_id"], "reason": reason}
    else:
        assert stored_block is None


@pytest.mark.parametrize(("distort", "reason"), [
    (wrapped_global, "snapshot scope unsupported"),
    (wrapped_vdom, "snapshot scope unsupported"),
    (vdoms_enabled, "snapshot scope unsupported"),
    (cut_before_table, "snapshot incomplete"),
    (without_header, "snapshot incomplete"),
    (other_build, "snapshot firmware mismatch"),
])
def test_fortios_snapshot_problem_after_the_change_names_its_cause_and_blocks(tmp_path, distort, reason):
    device = after_change(FakeFortiOS(), distort)
    runtime = fortios_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", fortios_request())
    assert device.distorted is True
    check_reason(tmp_path, runtime, record, "lab", reason, blocked=True)
    assert "new-host" not in device.addresses


@pytest.mark.parametrize("distort", [cut_inside_table, cut_inside_quote])
def test_fortios_dump_cut_inside_a_section_is_incomplete_and_blocks_like_a_cut_at_a_boundary(tmp_path, distort):
    device = after_change(FakeFortiOS(), distort)
    runtime = fortios_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", fortios_request())
    assert device.distorted is True
    check_reason(tmp_path, runtime, record, "lab", "snapshot incomplete", blocked=True)
    assert "new-host" not in device.addresses


@pytest.mark.parametrize("distort", [cut_inside_table, cut_inside_quote])
def test_fortios_dump_cut_before_the_change_is_refused_as_incomplete_without_block(tmp_path, distort):
    device = FakeFortiOS()
    original = device.snapshot
    device.snapshot = lambda: distort(original())
    runtime = fortios_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", fortios_request())
    assert caught.value.reasons[0].startswith("snapshot is cut off: unterminated"), caught.value.reasons
    assert getattr(caught.value, "category", None) == "snapshot incomplete"
    assert runtime.store.blocked("lab") is None
    assert device.applied_blocks == []


def test_fortios_account_created_during_the_change_keeps_the_administrator_table_reason(tmp_path):
    device = FakeFortiOS()
    device.on_apply = lambda fake, lines: fake.admins.append("sneaky") if len(fake.applied_blocks) == 2 else None
    runtime = fortios_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", fortios_request())
    check_reason(tmp_path, runtime, record, "lab", "administrator table", blocked=True)


def test_fortios_account_entry_changed_during_the_change_keeps_the_administrator_table_reason(tmp_path):
    device = FakeFortiOS()
    device.on_apply = (lambda fake, lines: fake.admin_comments.update({"netops-rw": "changed"})
                       if len(fake.applied_blocks) == 2 else None)
    runtime = fortios_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", fortios_request())
    check_reason(tmp_path, runtime, record, "lab", "administrator table", blocked=True)


def test_exos_dump_cut_before_the_vlan_module_is_incomplete_not_an_account_change(tmp_path):
    device = after_change(FakeExos(), cut_before_vlan_module)
    runtime = exos_runtime(tmp_path, device)
    record = execute.apply(runtime, "sw", exos_request())
    assert device.distorted is True
    check_reason(tmp_path, runtime, record, "sw", "snapshot incomplete", blocked=True)


def test_exos_account_created_during_the_change_keeps_the_administrator_table_reason(tmp_path):
    device = FakeExos()
    device.on_apply = lambda fake, steps: fake.accounts.append("sneaky") if len(fake.applied_blocks) == 2 else None
    runtime = exos_runtime(tmp_path, device)
    record = execute.apply(runtime, "sw", exos_request())
    check_reason(tmp_path, runtime, record, "sw", "administrator table", blocked=True)


def test_rejection_without_a_snapshot_cause_after_the_change_is_not_called_an_account_change(tmp_path, monkeypatch):
    device = FakeFortiOS()
    runtime = fortios_runtime(tmp_path, device)
    verify = engine.verify

    def refusing(plan, raw, expect="after"):
        if expect == "after" and len(device.applied_blocks) == 2:
            raise Rejected(["the object cannot be evaluated"])
        return verify(plan, raw, expect)

    monkeypatch.setattr(execute.engine, "verify", refusing)
    record = execute.apply(runtime, "lab", fortios_request())
    check_reason(tmp_path, runtime, record, "lab", "postcheck rejected", blocked=True)


@pytest.mark.parametrize(("raw", "category"), [
    (b"#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0:vdom=0\n\xff\n", "snapshot unreadable"),
    (b"#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0:vdom=0\nconfig firewall address\n", "snapshot incomplete"),
    (b'#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0:vdom=0\nconfig system global\n    set hostname "fw\n',
     "snapshot incomplete"),
    (b"#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0:vdom=0\nconfig system global\nend\nend\n",
     "snapshot unreadable"),
    (b"#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0:vdom=0\nconfig system global\nend\n",
     "snapshot incomplete"),
])
def test_snapshot_rejections_carry_their_category(fortios_snapshot, raw, category):
    plan = engine.build_plan("fortios", fortios_snapshot, parse_request(request_bytes()))
    with pytest.raises(Rejected) as caught:
        engine.verify(plan, raw, expect="before")
    assert getattr(caught.value, "category", None) == category
