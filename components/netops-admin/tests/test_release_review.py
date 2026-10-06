from __future__ import annotations

import json
import multiprocessing
import time
from pathlib import Path

import pytest
from conftest import request_bytes
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request, steps
from test_fortios import rejected
from test_port_inventory import FACTORY, FIRMWARE, TWELVE

from netops_admin import engine, execute
from netops_admin.errors import Rejected
from netops_admin.request import parse_request
from netops_admin.state import Store, read_json, write_atomic

PROCESSES = 4
ROUNDS = 100


@pytest.mark.parametrize("seconds", [60, 180, 900])
def test_every_allowed_safeguard_time_ends_with_a_true_result(tmp_path, seconds):
    device = FakeFortiOS()
    device.drop_comment = True
    runtime = make_runtime(tmp_path, device, safeguard_seconds=seconds)
    record = execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "two words"}))
    assert record["result"] == "reverted", (record["result"], steps(record)[-3:])
    assert record["reason"] == "prediction mismatch"
    assert device.addresses["spare-host"]["comment"] == "unused"
    assert runtime.store.blocked("lab") is None


def test_adding_a_protected_address_to_a_group_is_refused(fortios_snapshot):
    rejected(fortios_snapshot, "reference to protected object 'srv-web'",
             protected={"firewall address": ["srv-web"]}, table="firewall addrgrp", op="update", key="servers",
             changes={"member": ["grouped-host", "srv-web"]})


def test_removing_a_protected_address_from_a_group_is_refused(fortios_snapshot):
    rejected(fortios_snapshot, "reference to protected object 'grouped-host'",
             protected={"firewall address": ["grouped-host"]}, table="firewall addrgrp", op="update", key="servers",
             changes={"member": ["lab-net"]})


def test_protected_name_matches_a_reference_regardless_of_letter_case(fortios_snapshot):
    rejected(fortios_snapshot, "reference to protected object",
             protected={"firewall address": ["SRV-WEB"]}, table="firewall addrgrp", op="update", key="servers",
             changes={"member": ["grouped-host", "srv-web"]})


@pytest.mark.parametrize("changes", [{"tagged": ["guest"]}, {"untagged": "guest"}])
def test_port_membership_in_a_protected_vlan_is_refused(changes):
    body = parse_request(request_bytes(table="vlan-membership", op="update", key="5", changes=changes))
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", FACTORY.encode(), body, firmware=FIRMWARE, ports=TWELVE,
                          protected={"vlan": ["guest"]})
    assert any("reference to protected object 'guest'" in reason for reason in caught.value.reasons)


def test_request_for_another_device_is_refused_without_touching_the_device(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(device="fw-other"))
    assert any("fw-other" in reason for reason in caught.value.reasons)
    assert device.applied_blocks == [] and "new-host" not in device.addresses
    assert runtime.store.records() == []
    assert runtime.store.rejections_since(0) == 1


def test_preview_for_another_device_is_refused(tmp_path):
    device = FakeFortiOS()
    with pytest.raises(Rejected):
        execute.preview(make_runtime(tmp_path, device), "lab", request(device="fw-other"))
    assert device.applied_blocks == []


def test_request_naming_its_target_device_runs(tmp_path):
    device = FakeFortiOS()
    record = execute.apply(make_runtime(tmp_path, device), "lab", request(device="lab"))
    assert record["result"] == "confirmed"


def _note_rejections(root):
    store = Store(root)
    for _ in range(ROUNDS):
        store.note_rejection(time.time())


def _probe_journal(root):
    store = Store(root)
    for _ in range(ROUNDS):
        store.check_writable()


def _write_one_file(root):
    for round_ in range(ROUNDS):
        write_atomic(Path(root) / "shared.json", {"round": round_, "pad": "x" * 100000})


def _read_one_file(root):
    for _ in range(ROUNDS * 20):
        try:
            json.loads((Path(root) / "shared.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue


def _in_processes(target, root, reader=None):
    context = multiprocessing.get_context("fork")
    workers = [context.Process(target=target, args=(str(root),)) for _ in range(PROCESSES)]
    if reader is not None:
        workers.append(context.Process(target=reader, args=(str(root),)))
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(120)
    return [worker.exitcode for worker in workers]


def test_concurrent_rejections_are_all_counted(tmp_path):
    Store(tmp_path)
    assert _in_processes(_note_rejections, tmp_path) == [0] * PROCESSES
    assert Store(tmp_path).rejections_since(0) == PROCESSES * ROUNDS
    assert not list(tmp_path.glob(".*.tmp"))


def test_concurrent_journal_probes_do_not_refuse_each_other(tmp_path):
    Store(tmp_path)
    assert _in_processes(_probe_journal, tmp_path) == [0] * PROCESSES
    assert not list(tmp_path.glob(".*"))


def test_concurrent_atomic_writes_of_one_file_do_not_collide(tmp_path):
    assert _in_processes(_write_one_file, tmp_path, _read_one_file) == [0] * (PROCESSES + 1)
    assert read_json(tmp_path / "shared.json")["round"] == ROUNDS - 1
    assert [path.name for path in tmp_path.iterdir()] == ["shared.json"]


@pytest.mark.parametrize("content", [b"[1700000000.0, 17", b"{}", b'["x"]', b"\xff"])
def test_unreadable_rejection_count_refuses_the_request_in_order(tmp_path, content):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    (tmp_path / "state" / "rejections.json").write_bytes(content)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert any("rejections.json" in reason for reason in caught.value.reasons)
    assert device.applied_blocks == [] and "new-host" not in device.addresses
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(device="fw-other"))
    assert any("fw-other" in reason for reason in caught.value.reasons)
    assert (tmp_path / "state" / "rejections.json").read_bytes() == content


@pytest.mark.parametrize("protected, member", [("srv-web", "SRV-WEB"), ("SRV-Web", "Srv-wEB")])
def test_reference_in_other_letter_case_than_the_protected_name_is_refused(fortios_snapshot, protected, member):
    rejected(fortios_snapshot, "reference to protected object",
             protected={"firewall address": [protected]}, table="firewall addrgrp", op="update", key="servers",
             changes={"member": ["grouped-host", member]})


@pytest.mark.parametrize("changes", [{"tagged": ["Guest"]}, {"untagged": "GUEST"}])
def test_vlan_in_other_letter_case_than_the_protected_name_is_refused(changes):
    body = parse_request(request_bytes(table="vlan-membership", op="update", key="5", changes=changes))
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", FACTORY.encode(), body, firmware=FIRMWARE, ports=TWELVE,
                          protected={"vlan": ["guest"]})
    assert any("reference to protected object" in reason for reason in caught.value.reasons)


@pytest.mark.parametrize("failing", ["replace", "fsync"])
def test_failed_atomic_write_leaves_no_temporary_file(tmp_path, monkeypatch, failing):
    from netops_admin import state

    def refuse(*_args):
        raise OSError("refused by the test")

    monkeypatch.setattr(state.os, failing, refuse)
    with pytest.raises(OSError):
        write_atomic(tmp_path / "record.json", {"a": 1})
    monkeypatch.undo()
    assert list(tmp_path.iterdir()) == []
