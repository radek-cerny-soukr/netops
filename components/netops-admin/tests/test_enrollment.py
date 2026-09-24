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
