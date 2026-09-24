import json
from dataclasses import replace

import pytest

from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request
from netops_admin import audit_gate, execute
from netops_admin.errors import Rejected


def with_policy(runtime, **values):
    device = runtime.config.devices["lab"]
    policy = {"version": 1, "platform": "fortios", **values}
    runtime.config = replace(runtime.config, devices={"lab": replace(device, audit_policy=policy)})
    from enrollment_helpers import certify
    return certify(runtime, runtime.access_factory(device), "lab")


def test_disallowed_address_is_rejected_before_safeguard_installation(tmp_path):
    target = FakeFortiOS()
    runtime = with_policy(make_runtime(tmp_path, target), address_networks=["198.51.100.0/24"])
    with pytest.raises(Rejected, match="violates"):
        execute.apply(runtime, "lab", request())
    assert target.applied_blocks == []


def test_allowed_address_succeeds_with_coverage_report(tmp_path):
    target = FakeFortiOS()
    runtime = with_policy(make_runtime(tmp_path, target), address_networks=["192.0.2.0/24"])
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "confirmed"
    assert record["audit_coverage"]["address-policy"] == "evaluated"


def test_old_policy_violation_does_not_allow_editing_a_still_disallowed_object(tmp_path):
    target = FakeFortiOS()
    runtime = with_policy(make_runtime(tmp_path, target), address_networks=["198.51.100.0/24"])
    with pytest.raises(Rejected, match="violates"):
        execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "changed"}))
    assert target.applied_blocks == []


def test_required_unconfigured_check_refuses_before_mutation(tmp_path):
    target = FakeFortiOS()
    runtime = with_policy(make_runtime(tmp_path, target), required_rules=["address-policy"])
    with pytest.raises(Rejected, match="not evaluated"):
        execute.apply(runtime, "lab", request())
    assert target.applied_blocks == []


def test_changed_evidence_for_an_existing_blocking_finding_is_not_silenced():
    before_text = "# Module vlan configuration.\n"
    before_text += "configure vlan one add ports 10 untagged\nconfigure vlan two add ports 10 untagged\n"
    after_text = before_text + "configure vlan three add ports 10 untagged\n"
    before = audit_gate.findings("exos", before_text, "switch-example")
    assert audit_gate.new_blocking("exos", before, after_text, "switch-example") == ["exos.management.port-native"]


def test_policy_cannot_be_injected_in_a_change_request():
    from netops_admin.request import parse_request
    data = {"table": "firewall address", "op": "create", "key": "host-example",
            "changes": {"subnet": "192.0.2.20/32"}, "reason": "example",
            "user_request": "example", "request_id": "example-request", "audit_policy": {}}
    with pytest.raises(Rejected):
        parse_request(json.dumps(data).encode())


def test_foreign_change_in_another_fortios_table_is_detected(fortios_snapshot):
    from netops_admin import engine
    plan = engine.build_plan("fortios", fortios_snapshot, request())
    changed = fortios_snapshot + b'config system global\n set admin-sport 10443\nend\n'
    verdict = engine.verify(plan, changed, expect="before")
    assert verdict["object_matches"]
    assert not verdict["rest_matches"]
