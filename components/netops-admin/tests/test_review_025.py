from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest
from conftest import FIXTURES, request_bytes
from fake_fortios import FakeFortiOS
from test_enrollment import ready
from test_execute import audit_lines, make_runtime, request, steps
from test_export_status import export_status

from netops_admin import engine, enrollment, execute, readiness
from netops_admin.access import AccessError
from netops_admin.cli import EXIT_REJECTED, main
from netops_admin.config import load_config
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

UNREADABLE = [b"{broken", b"\xff\xfe", b'["x"]']
OPERATION = "operations/" + "e" * 32 + ".json"
STATE_FILES = [OPERATION, "requests/req-0001-example.json", "blocked/lab.json", "baselines/lab.json",
               "enrollments/lab.json"]
PROCESSES = 4
ROUNDS = 100


def _plan():
    body = parse_request(request_bytes(op="update", key="spare-host", changes={"comment": "reserved"}))
    return engine.build_plan("fortios", (FIXTURES / "fortios_8_0_0.conf").read_bytes(), body)


def _changed(field, value):
    plan = _plan()
    if field.startswith("predicted."):
        plan["predicted"][field.split(".")[1]] = value
    else:
        plan[field] = value
    plan["plan_sha256"] = engine._digest({"commands": plan["commands"], "inverse": plan["inverse"],
                                          "before": plan["predicted"]["before"],
                                          "after": plan["predicted"]["after"]})
    return plan


@pytest.mark.parametrize("field, value", [
    ("key", 5), ("key", None), ("key", ["x"]), ("platform", ["fortios"]), ("platform", "junos"),
    ("table", {"a": 1}), ("safeguard_id", 5), ("safeguard_id", True), ("op", "rename"), ("prechecks", "junk"),
    ("commands", [5]), ("inverse", "x"), ("firmware", 7), ("rest_sha256", None), ("reason_characters", True),
    ("predicted.before", "text"), ("predicted.before", ["x"]), ("predicted.after", 5),
])
def test_plan_with_a_value_of_the_wrong_type_is_refused_by_verify(tmp_path, capsys, field, value):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(_changed(field, value)), encoding="utf-8")
    code = main(["verify", "--plan", str(path), "--snapshot", str(FIXTURES / "fortios_8_0_0.conf"),
                 "--expect", "before"])
    document = json.loads(capsys.readouterr().out)
    assert (code, document["result"]) == (EXIT_REJECTED, "rejected")
    assert "plan" in document["reasons"][0]


def test_unchanged_plan_still_matches_after_the_type_checks():
    assert engine.verify(_plan(), (FIXTURES / "fortios_8_0_0.conf").read_bytes(), expect="before")["result"] == "match"


def _config(tmp_path, **notify):
    body = {"server": "https://ntfy.example.invalid", "topic_file": "/etc/netops-admin/topic.env"}
    body.update(notify)
    device = {"platform": "fortios", "address": "192.0.2.1", "host_key_fingerprint": "SHA256:" + "A" * 43,
              "vault": "/etc/netops-admin/vault.json", "credential": "rw", "check_credential": "ro"}
    path = tmp_path / "admin.json"
    path.write_text(json.dumps({"version": 1, "state_dir": "/var/lib/a", "audit_file": "/var/lib/a/audit.jsonl",
                                "notify": body, "devices": {"fw-lab": device}}))
    return path


@pytest.mark.parametrize("value", [-1, 0, 0.5, 61, 10 ** 9, float("nan"), float("inf"), "10", "abc", True, None])
def test_notification_timeout_outside_its_range_is_refused(tmp_path, value):
    with pytest.raises(Rejected) as caught:
        load_config(_config(tmp_path, timeout_seconds=value))
    assert "timeout_seconds" in caught.value.reasons[0]


@pytest.mark.parametrize("value, expected", [(1, 1.0), (2.5, 2.5), (60, 60.0)])
def test_notification_timeout_inside_its_range_loads(tmp_path, value, expected):
    assert load_config(_config(tmp_path, timeout_seconds=value)).notify.timeout_seconds == expected


def test_notification_timeout_defaults_to_ten_seconds(tmp_path):
    assert load_config(_config(tmp_path)).notify.timeout_seconds == 10.0


def _interrupted(tmp_path):
    device = FakeFortiOS()
    blocks = []

    def crash(fake, lines):
        blocks.append(lines)
        if len(blocks) == 2:
            fake._run(lines)
            raise KeyboardInterrupt

    device.on_apply = crash
    with pytest.raises(KeyboardInterrupt):
        execute.apply(make_runtime(tmp_path, device), "lab", request())
    device.on_apply = None
    return device


def _unreachable(_device):
    raise AccessError("connection refused by the test")


def test_recover_of_an_unreachable_device_finishes_the_operation_and_records_it(tmp_path):
    runtime = make_runtime(tmp_path, _interrupted(tmp_path))
    runtime.access_factory = _unreachable
    settled = execute.recover(runtime, "lab")
    assert [(record["result"], record["reason"]) for record in settled] == [
        ("unknown", "interrupted; device unreachable")]
    assert "recovery_access_failed" in steps(settled[0])
    assert runtime.store.running("lab") == []
    assert runtime.store.blocked("lab")["change_id"] == settled[0]["change_id"]
    results = [event for event in audit_lines(tmp_path) if event["event"] == "result"]
    assert results[-1]["change_id"] == settled[0]["change_id"] and results[-1]["result"] == "unknown"


def test_recover_settles_an_operation_without_a_safeguard_without_the_device(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    runtime.access_factory = _unreachable
    (tmp_path / "audit").mkdir()
    runtime.store.save({"change_id": "d" * 32, "request_id": "req-interrupted", "device": "lab",
                        "status": "running", "plan": {"platform": "fortios"}, "steps": []})
    settled = execute.recover(runtime, "lab")
    assert [(record["result"], record["reason"]) for record in settled] == [
        ("rejected", "interrupted before any mutation")]


def test_enroll_with_an_invalid_probe_keeps_the_valid_enrollment(tmp_path):
    runtime, target, name = ready(tmp_path)
    assert enrollment.run(runtime, name, "192.0.2.254/32")["enrollment"] == "valid"
    certificate = runtime.store.enrollment(name)
    with pytest.raises(Rejected):
        enrollment.run(runtime, name, "banana")
    assert runtime.store.enrollment(name) == certificate
    assert execute.apply(runtime, name, request())["result"] == "confirmed"


def test_failed_enrollment_notification_keeps_the_valid_enrollment(tmp_path):
    runtime, target, name = ready(tmp_path)
    enrollment.run(runtime, name, "192.0.2.254/32")
    certificate = runtime.store.enrollment(name)
    blocks = len(target.applied_blocks)
    runtime.notifier = lambda record: "failed"
    refused = enrollment.run(runtime, name, "192.0.2.254/32")
    assert refused["result"] == "rejected"
    assert len(target.applied_blocks) == blocks
    assert runtime.store.enrollment(name) == certificate
    runtime.notifier = lambda record: "sent"
    assert execute.notify_retry(runtime, refused["change_id"])["notification"] == "sent"
    assert execute.apply(runtime, name, request())["result"] == "confirmed"


def test_enrollment_probe_that_fails_on_the_device_removes_the_enrollment(tmp_path):
    runtime, target, name = ready(tmp_path)
    enrollment.run(runtime, name, "192.0.2.254/32")
    start = len(target.applied_blocks)

    def hook(fake, lines):
        if len(fake.applied_blocks) == start + 2:
            fake.check_unreadable = True

    target.on_apply = hook
    record = enrollment.run(runtime, name, "192.0.2.254/32")
    assert record.get("enrollment") is None
    assert runtime.store.enrollment(name) is None


def test_unblock_of_a_device_that_is_not_blocked_keeps_its_account_reference(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"
    kept = runtime.store.baseline("lab")
    assert kept is not None
    events = audit_lines(tmp_path)
    assert execute.unblock(runtime, "lab", "nothing to lift") is False
    assert runtime.store.baseline("lab") == kept
    assert audit_lines(tmp_path) == events


def test_unblock_of_a_blocked_device_still_drops_the_account_reference(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"
    runtime.store.block("lab", None, "administrator table")
    assert execute.unblock(runtime, "lab", "investigated") is True
    assert runtime.store.baseline("lab") is None
    assert audit_lines(tmp_path)[-1]["action"] == "unblock"


def test_preview_of_a_reused_request_id_with_other_content_is_refused_like_apply(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"
    other = request(changes={"subnet": "192.0.2.31/32", "comment": "other host"})
    previewed = execute.preview(runtime, "lab", other)
    assert previewed["result"] == "rejected"
    assert previewed["reasons"] == ["request_id was already used for a different request"]
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", other)
    assert caught.value.reasons == previewed["reasons"]
    assert "192.0.2.31" not in json.dumps(device.addresses)


def _spoil(tmp_path, name, content):
    path = tmp_path / "state" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _names(reasons, name):
    return any(name in reason and "a person must check it" in reason for reason in reasons)


@pytest.mark.parametrize("content", UNREADABLE)
@pytest.mark.parametrize("name", STATE_FILES)
def test_unreadable_state_file_refuses_apply_with_a_clear_reason(tmp_path, name, content):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    _spoil(tmp_path, name, content)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert _names(caught.value.reasons, name)
    assert device.applied_blocks == []
    assert (tmp_path / "state" / name).read_bytes() == content
    if name != "blocked/lab.json":
        assert not (tmp_path / "state" / "blocked" / "lab.json").exists()


@pytest.mark.parametrize("content", UNREADABLE)
@pytest.mark.parametrize("name", STATE_FILES)
def test_unreadable_state_file_refuses_preview_with_a_clear_reason(tmp_path, name, content):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    _spoil(tmp_path, name, content)
    result = execute.preview(runtime, "lab", request())
    assert result["result"] == "rejected"
    assert _names(result["reasons"], name)


@pytest.mark.parametrize("content", UNREADABLE)
@pytest.mark.parametrize("name", [OPERATION, "blocked/lab.json", "baselines/lab.json", "enrollments/lab.json"])
def test_unreadable_state_file_is_reported_by_doctor(tmp_path, name, content):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    _spoil(tmp_path, name, content)
    report = readiness.doctor(runtime, "lab")
    assert report["ready"] is False
    assert _names([item["detail"] or "" for item in report["checks"]], name)


@pytest.mark.parametrize("content", UNREADABLE)
def test_unreadable_operation_refuses_recover_with_a_clear_reason(tmp_path, content):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    _spoil(tmp_path, OPERATION, content)
    with pytest.raises(Rejected) as caught:
        execute.recover(runtime, "lab")
    assert _names(caught.value.reasons, OPERATION)


def test_rejection_count_that_cannot_be_opened_refuses_apply_and_preview(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    (tmp_path / "state" / "rejections.json").mkdir()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert any("rejections.json" in reason for reason in caught.value.reasons)
    result = execute.preview(runtime, "lab", request())
    assert result["result"] == "rejected" and "rejections.json" in result["reasons"][0]
    assert device.applied_blocks == []


def test_export_status_is_not_written_through_a_planted_temporary_file(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    output = tmp_path / "export-status.json"
    (tmp_path / ".export-status.json.tmp").symlink_to(victim)
    export_status.write_status(output, 0, 1000.0)
    assert victim.read_text() == "keep"
    assert not output.is_symlink() and json.loads(output.read_text())["updated_at"] == 1000.0


def _write_statuses(root):
    for round_ in range(ROUNDS):
        export_status.write_status(Path(root) / "export-status.json", 0, float(round_))


def test_concurrent_export_status_writers_do_not_collide(tmp_path):
    context = multiprocessing.get_context("fork")
    workers = [context.Process(target=_write_statuses, args=(str(tmp_path),)) for _ in range(PROCESSES)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(120)
    assert [worker.exitcode for worker in workers] == [0] * PROCESSES
    assert [path.name for path in tmp_path.iterdir()] == ["export-status.json"]


def test_failed_export_status_write_leaves_no_temporary_file(tmp_path, monkeypatch):
    def refuse(*_args):
        raise OSError("refused by the test")

    monkeypatch.setattr(export_status.os, "replace", refuse)
    with pytest.raises(OSError):
        export_status.write_status(tmp_path / "export-status.json", 0, 1000.0)
    monkeypatch.undo()
    assert list(tmp_path.iterdir()) == []


REQUEST_FILE = "requests/req-0001-example.json"


@pytest.mark.parametrize("change", [
    {"change_id": None}, {"request_sha256": None}, {"device": None}, {"change_id": 5}, {"change_id": "../other"},
])
def test_request_document_without_its_fields_refuses_apply_and_preview(tmp_path, change):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    document = {"request_id": "req-0001-example", "change_id": "e" * 32, "request_sha256": request().fingerprint(),
                "device": "lab"}
    document.update(change)
    _spoil(tmp_path, REQUEST_FILE, json.dumps({k: v for k, v in document.items() if v is not None}).encode())
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert _names(caught.value.reasons, REQUEST_FILE)
    result = execute.preview(runtime, "lab", request())
    assert result["result"] == "rejected" and _names(result["reasons"], REQUEST_FILE)
    assert device.applied_blocks == []


def test_request_whose_operation_file_is_missing_is_refused(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    record = execute.apply(runtime, "lab", request())
    name = "operations/%s.json" % record["change_id"]
    (tmp_path / "state" / name).unlink()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert _names(caught.value.reasons, name)
    result = execute.preview(runtime, "lab", request())
    assert result["result"] == "rejected" and _names(result["reasons"], name)


@pytest.mark.parametrize("document", [{}, {"device": "lab", "status": "running"},
                                      {"change_id": "e" * 32, "request_id": "r", "device": "lab", "status": 5}])
def test_operation_document_without_its_fields_refuses_recover_and_apply(tmp_path, document):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    _spoil(tmp_path, OPERATION, json.dumps(document).encode())
    with pytest.raises(Rejected) as caught:
        execute.recover(runtime, "lab")
    assert _names(caught.value.reasons, OPERATION)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert _names(caught.value.reasons, OPERATION)


@pytest.mark.parametrize("content", UNREADABLE)
def test_doctor_reports_an_unreadable_enrollment_as_refused(tmp_path, content):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    _spoil(tmp_path, "enrollments/lab.json", content)
    checks = {item["check"]: item for item in readiness.doctor(runtime, "lab")["checks"]}
    assert checks["enrollment"]["status"] == "refused"
    assert _names([checks["enrollment"]["detail"]], "enrollments/lab.json")


def test_doctor_still_reports_a_missing_enrollment_as_missing(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    runtime.store.clear_enrollment("lab")
    checks = {item["check"]: item["status"] for item in readiness.doctor(runtime, "lab")["checks"]}
    assert checks["enrollment"] == "missing"


def test_pending_since_is_not_written_through_a_planted_link(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    output = tmp_path / "export-status.json"
    since = tmp_path / "export-status.json.pending-since"
    since.symlink_to(victim)
    assert export_status.write_status(output, 3, 1000.0)["oldest_pending_age_seconds"] == 0
    assert victim.read_text() == "keep"
    assert not since.is_symlink() and float(since.read_text()) == 1000.0
    assert export_status.write_status(output, 3, 1060.0)["oldest_pending_age_seconds"] == 60.0


def test_failed_pending_since_write_leaves_no_file(tmp_path, monkeypatch):
    def refuse(*_args):
        raise OSError("refused by the test")

    monkeypatch.setattr(export_status.os, "replace", refuse)
    with pytest.raises(OSError):
        export_status.write_status(tmp_path / "export-status.json", 3, 1000.0)
    monkeypatch.undo()
    assert list(tmp_path.iterdir()) == []


def test_request_id_reused_on_another_device_is_refused_by_apply_and_preview(tmp_path):
    import dataclasses

    from enrollment_helpers import certify

    first, second = FakeFortiOS(), FakeFortiOS(hostname="fw-lab2")
    runtime = make_runtime(tmp_path, first)
    lab = runtime.config.devices["lab"]
    runtime.config = dataclasses.replace(runtime.config, devices={
        "lab": lab, "lab2": dataclasses.replace(lab, name="lab2", address="192.0.2.2")})
    targets = {"lab": first, "lab2": second}
    runtime.access_factory = lambda device: targets[device.name]
    certify(runtime, second, "lab2")
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"
    previewed = execute.preview(runtime, "lab2", request())
    assert previewed["result"] == "rejected" and previewed["reasons"] == [execute.REUSED_REQUEST]
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab2", request())
    assert caught.value.reasons == [execute.REUSED_REQUEST]
    assert second.applied_blocks == [] and "new-host" not in second.addresses
