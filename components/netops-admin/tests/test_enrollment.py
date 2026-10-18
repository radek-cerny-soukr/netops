import json
import time
from dataclasses import replace

import pytest

from fake_fortios import FakeFortiOS
from fake_exos import FakeExos
from test_execute import make_runtime, request
from test_execute_exos import make_runtime as make_exos_runtime
from netops_admin import enrollment, execute
from netops_admin.errors import Rejected


def ready(tmp_path, platform="fortios"):
    target = FakeFortiOS() if platform == "fortios" else FakeExos()
    runtime = make_runtime(tmp_path, target) if platform == "fortios" else make_exos_runtime(tmp_path, target)
    name = "lab" if platform == "fortios" else "sw"
    runtime.store.clear_enrollment(name)
    status = tmp_path / "export.json"
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 0}))
    runtime.config = replace(runtime.config, export_status_file=str(status))
    runtime.notifier = lambda record: "sent"
    return runtime, target, name


def test_apply_without_enrollment_cannot_install_a_safeguard(tmp_path):
    runtime, target, name = ready(tmp_path)
    with pytest.raises(Rejected, match="enroll"):
        execute.apply(runtime, name, request())
    assert target.applied_blocks == []


@pytest.mark.parametrize("platform,probe", [("fortios", "192.0.2.254/32"), ("exos", "3998")])
def test_enrollment_requires_observed_change_then_actual_timer_return(tmp_path, platform, probe):
    runtime, target, name = ready(tmp_path, platform)
    before = target.snapshot()
    record = enrollment.run(runtime, name, probe)
    assert record["result"] == "reverted"
    assert record["enrollment"] == "valid"
    assert runtime.store.enrollment(name)["change_id"] == record["change_id"]
    assert target.snapshot() == before
    steps = [item["step"] for item in record["steps"]]
    assert "check_identity_passed" in steps and "confirm_start" not in steps


def test_successful_enrollment_allows_a_normal_change(tmp_path):
    runtime, target, name = ready(tmp_path)
    enrollment.run(runtime, name, "192.0.2.254/32")
    assert execute.apply(runtime, name, request())["result"] == "confirmed"


def test_enrollment_is_refused_when_the_export_status_covers_another_audit_file(tmp_path):
    runtime, target, name = ready(tmp_path)
    with open(runtime.config.export_status_file, "w") as handle:
        json.dump({"updated_at": time.time(), "pending": 0, "audit_file": "/var/lib/netops-admin-audit/audit.jsonl"}, handle)
    with pytest.raises(Rejected, match="another audit file"):
        enrollment.run(runtime, name, "192.0.2.254/32")
    assert target.applied_blocks == []
    assert runtime.store.enrollment(name) is None


def test_failed_notification_prevents_probe_write_and_invalidates_previous_result(tmp_path):
    runtime, target, name = ready(tmp_path)
    runtime.notifier = lambda record: "failed"
    record = enrollment.run(runtime, name, "192.0.2.254/32")
    assert record["result"] == "rejected"
    assert runtime.store.enrollment(name) is None
    assert target.applied_blocks == []


def test_new_policy_requires_new_enrollment(tmp_path):
    runtime, target, name = ready(tmp_path)
    enrollment.run(runtime, name, "192.0.2.254/32")
    changed = replace(runtime.config.devices[name], audit_policy={"version": 1, "platform": "fortios"})
    runtime.config = replace(runtime.config, devices={name: changed})
    with pytest.raises(Rejected, match="enroll"):
        execute.apply(runtime, name, request())


def test_changed_build_invalidates_enrollment_binding(tmp_path):
    runtime, target, name = ready(tmp_path)
    enrollment.run(runtime, name, "192.0.2.254/32")
    device = runtime.config.devices[name]
    old = runtime.store.enrollment(name)
    assert old["binding"] != enrollment.binding(device, "accounts", "7.6.8 build9999", runtime.config)


def test_lost_check_account_during_probe_does_not_certify(tmp_path):
    runtime, target, name = ready(tmp_path)
    def hook(fake, lines):
        if len(fake.applied_blocks) == 2:
            fake.check_unreadable = True
    target.on_apply = hook
    record = enrollment.run(runtime, name, "192.0.2.254/32")
    assert record.get("enrollment") is None
    assert runtime.store.enrollment(name) is None


def test_probe_namespace_cannot_be_requested_over_normal_apply(tmp_path):
    runtime, target, name = ready(tmp_path)
    with pytest.raises(Rejected, match="reserved"):
        execute.apply(runtime, name, request(key="netops-enroll-example"))
    assert target.applied_blocks == []

@pytest.mark.parametrize("platform,probe", [("fortios", "192.0.2.254/32"), ("exos", "3998")])
def test_unified_context_enrolls_with_local_operation_audit_without_claiming_export(tmp_path, platform, probe):
    from netops_admin import readiness
    from netops_admin.config import Notify
    runtime, target, name = ready(tmp_path, platform)
    runtime.require_export = False
    runtime.config = replace(runtime.config, export_status_file=None,
                             notify=Notify("https://notify.example.invalid", str(tmp_path / "topic"), 10.0, True))
    before = target.snapshot()
    record = enrollment.run(runtime, name, probe)
    assert record["enrollment"] == "valid" and record["result"] == "reverted"
    assert record["audit_delivery"] == "not-configured" and record["notification"] == "sent"
    assert target.snapshot() == before
    report = readiness.doctor(runtime, name)
    assert report["ready"] is True
    checks = {item["check"]: item for item in report["checks"]}
    assert checks["operation audit configuration"]["status"] == readiness.OK
    assert "no independent export delivery claimed" in checks["operation audit configuration"]["detail"]
    assert "audit export" not in checks


@pytest.mark.parametrize("failure", ["stale", "missing"])
def test_unified_context_keeps_configured_export_failures_blocking(tmp_path, failure):
    from netops_admin import readiness
    runtime, target, name = ready(tmp_path)
    runtime.require_export = False
    if failure == "stale":
        with open(runtime.config.export_status_file, "w") as stream:
            json.dump({"updated_at": time.time() - 10000, "pending": 0}, stream)
    else:
        __import__("pathlib").Path(runtime.config.export_status_file).unlink()
    with pytest.raises(Rejected, match="audit export is blocked"):
        enrollment.run(runtime, name, "192.0.2.254/32")
    assert target.applied_blocks == []
    assert readiness.doctor(runtime, name)["ready"] is False


def test_unified_context_keeps_local_audit_failure_blocking(tmp_path, monkeypatch):
    runtime, target, name = ready(tmp_path)
    runtime.require_export = False
    runtime.config = replace(runtime.config, export_status_file=None)
    def unavailable():
        raise Rejected(["synthetic operation audit unavailable"])
    monkeypatch.setattr(runtime.audit, "check_writable", unavailable)
    with pytest.raises(Rejected, match="operation audit unavailable"):
        enrollment.run(runtime, name, "192.0.2.254/32")
    assert target.applied_blocks == []


def test_unified_context_still_requires_actual_notification_before_probe(tmp_path):
    runtime, target, name = ready(tmp_path)
    runtime.require_export = False
    runtime.config = replace(runtime.config, export_status_file=None)
    runtime.notifier = lambda record: "failed"
    record = enrollment.run(runtime, name, "192.0.2.254/32")
    assert record["result"] == "rejected" and record.get("enrollment") is None
    assert target.applied_blocks == []
