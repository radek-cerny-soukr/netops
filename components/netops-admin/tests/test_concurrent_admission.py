from __future__ import annotations

import dataclasses
import multiprocessing

import pytest
from conftest import request_bytes
from enrollment_helpers import certify
from fake_fortios import FakeFortiOS
from test_enrollment import ready
from test_execute import make_runtime, request
from test_schema_execute import runtime as schema_runtime
from test_schema_plan import op
from test_schema_runtime import request as schema_request

from netops_admin import enrollment, execute, state
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FORK = multiprocessing.get_context("fork")
WAIT_SECONDS = 60
DEVICE = Device(
    name="lab-a", platform="fortios", address="192.0.2.1", port=22, host_key_fingerprint="SHA256:" + "A" * 43,
    vault="/nonexistent/vault.json", credential="rw", check_credential="ro", firmware=None, safeguard_seconds=180,
    confirm_margin_seconds=45, protected={},
)
REQUESTS = {
    "lab-a": {"key": "host-a", "changes": {"subnet": "192.0.2.61/32"}, "request_id": "req-race-a-0001"},
    "lab-b": {"key": "host-b", "changes": {"subnet": "192.0.2.62/32"}, "request_id": "req-race-b-0001"},
}
ADMISSION_REFUSED = "another operation holds the admission lock of the journal"


def configured(tmp_path, **limits):
    devices = {name: dataclasses.replace(DEVICE, name=name, address="192.0.2.%d" % number)
               for number, name in enumerate(REQUESTS, 1)}
    config = Config(state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
                    export_status_file=None, notify=None, limits=dict(DEFAULT_LIMITS, **limits), devices=devices)
    runtime = execute.Runtime(config, lambda _device: FakeFortiOS())
    for name in devices:
        certify(runtime, FakeFortiOS(), name)
    return config


def client(config, name, fields, barrier, results):
    device = FakeFortiOS()
    runtime = execute.Runtime(config, lambda _device: device, sleep=device.advance)
    checked = execute._prepared

    def held(*args, **kwargs):
        prepared = checked(*args, **kwargs)
        barrier.wait(WAIT_SECONDS)
        return prepared

    execute._prepared = held
    try:
        record = execute.apply(runtime, name, parse_request(request_bytes(**fields)))
    except Rejected as exc:
        results.put((name, type(exc).__name__, list(exc.reasons)))
    except BaseException as exc:
        results.put((name, "error", repr(exc)))
    else:
        results.put((name, record["result"], record["change_id"]))


def race(config, requests):
    barrier, results = FORK.Barrier(len(requests)), FORK.Queue()
    clients = [FORK.Process(target=client, args=(config, name, fields, barrier, results), daemon=True)
               for name, fields in requests.items()]
    for process in clients:
        process.start()
    try:
        return {name: (outcome, detail) for name, outcome, detail in
                (results.get(timeout=WAIT_SECONDS) for _process in clients)}
    finally:
        for process in clients:
            process.join(WAIT_SECONDS)
            if process.is_alive():
                process.kill()
                process.join(WAIT_SECONDS)


def test_changes_on_two_devices_at_once_share_the_daily_budget(tmp_path):
    config = configured(tmp_path, changes_per_day=1)
    outcomes = race(config, REQUESTS)
    assert sorted(outcome for outcome, _detail in outcomes.values()) == ["BudgetExhausted", "confirmed"]
    assert [detail for outcome, detail in outcomes.values() if outcome == "BudgetExhausted"] == [
        ["the budget of changes for this day is exhausted"]]
    assert [record["result"] for record in execute.Store(config.state_dir).records()] == ["confirmed"]


def test_one_request_id_on_two_devices_at_once_starts_one_operation(tmp_path):
    config = configured(tmp_path)
    shared = {name: dict(fields, request_id="req-race-shared-01") for name, fields in REQUESTS.items()}
    outcomes = race(config, shared)
    assert sorted(outcome for outcome, _detail in outcomes.values()) == ["Rejected", "confirmed"]
    [winner] = [name for name, (outcome, _detail) in outcomes.items() if outcome == "confirmed"]
    [loser] = [name for name in shared if name != winner]
    change_id = outcomes[winner][1]
    assert outcomes[loser][1] == [execute.REUSED_REQUEST]
    store = execute.Store(config.state_dir)
    known = store.request("req-race-shared-01")
    assert (known["device"], known["change_id"]) == (winner, change_id)
    assert [record["change_id"] for record in store.records()] == [change_id]
    runtime = execute.Runtime(config, lambda _device: FakeFortiOS())
    again = execute.apply(runtime, winner, parse_request(request_bytes(**shared[winner])))
    assert again["change_id"] == change_id and again["result"] == "confirmed"


def _new_change(tmp_path, monkeypatch):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    return runtime, device, lambda: execute.apply(runtime, "lab", request())


def _new_transaction(tmp_path, monkeypatch):
    runtime, device = schema_runtime(tmp_path, monkeypatch)
    return runtime, device, lambda: execute.apply(runtime, "lab", schema_request([op(changes={"comment": "final"})]))


def _new_undo(tmp_path, monkeypatch):
    runtime, device, start = _new_change(tmp_path, monkeypatch)
    change_id = start()["change_id"]
    return runtime, device, lambda: execute.undo(runtime, change_id, "investigated")


def _new_enrollment(tmp_path, monkeypatch):
    runtime, device, name = ready(tmp_path)
    return runtime, device, lambda: enrollment.run(runtime, name, "192.0.2.254/32")


@pytest.mark.parametrize("start", [_new_change, _new_transaction, _new_undo, _new_enrollment],
                         ids=["apply", "transaction", "undo", "enrollment"])
def test_every_new_operation_is_admitted_under_the_admission_lock(tmp_path, monkeypatch, start):
    runtime, device, begin = start(tmp_path, monkeypatch)
    monkeypatch.setattr(state, "ADMISSION_WAIT_SECONDS", 0.2)
    records, blocks = runtime.store.records(), len(device.applied_blocks)
    with runtime.store.admission():
        with pytest.raises(Rejected) as caught:
            begin()
    assert caught.value.reasons == [ADMISSION_REFUSED]
    assert runtime.store.records() == records and len(device.applied_blocks) == blocks


def test_the_admission_lock_is_free_while_the_device_is_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "ADMISSION_WAIT_SECONDS", 0)
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    free = []

    def probe(fake, lines):
        try:
            with runtime.store.admission():
                free.append(True)
        except Rejected:
            free.append(False)

    device.on_apply = probe
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"
    assert free and all(free)


def test_an_identical_request_admitted_meanwhile_returns_its_operation(tmp_path, monkeypatch):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = execute.apply(runtime, "lab", request())
    checked = execute._prepared

    def admitted_meanwhile(*args, **kwargs):
        prepared = checked(*args, **kwargs)
        runtime.store.remember_request("req-0002-example", first["change_id"], args[3].fingerprint(), "lab")
        return prepared

    monkeypatch.setattr(execute, "_prepared", admitted_meanwhile)
    blocks = len(device.applied_blocks)
    again = execute.apply(runtime, "lab", request(key="second-host", request_id="req-0002-example"))
    assert again["change_id"] == first["change_id"]
    assert len(device.applied_blocks) == blocks and len(runtime.store.records()) == 1
