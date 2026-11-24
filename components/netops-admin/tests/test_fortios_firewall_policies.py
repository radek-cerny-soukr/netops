"""FortiOS policy lifecycle through Admin and a simulated CLI with measured readbacks."""
from pathlib import Path

import pytest

from netops_admin import engine, execute, fortios, prediction, profiles
from netops_admin.errors import Rejected
from test_execute import request
from test_firewall_policy import FakeFortiOS, runtime

TABLE = "firewall policy"
FIRST, ANCHOR, SECOND, NEW = "220061", "220062", "220063", "220064"
FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_firewall_policies"
BASE = {"action": "accept", "status": "disable", "srcintf": ["dmz"], "dstintf": ["wan2"],
        "srcaddr": ["netops-firewall-policies-src"], "dstaddr": ["netops-firewall-policies-dst"], "schedule": "always",
        "service": ["HTTPS"], "logtraffic": "all", "name": "netops-firewall-policies-test"}


def fixture(label):
    return (FIXTURES / (label + ".txt")).read_text()


class MeasuredPolicies(FakeFortiOS):
    def __init__(self):
        super().__init__()
        self.interfaces.extend(("dmz", "wan2"))
        for name in ("netops-firewall-policies-src", "netops-firewall-policies-dst"):
            self.addresses[name] = {"uuid": self._uuid()}
        self.initial = {key: {name: attr.value() for name, attr in entry.attrs.items()}
                        for key, entry in fortios.parse_snapshot(fixture("sequence")).section(TABLE).entries.items()}
        self.policies = {key: dict(attrs) for key, attrs in self.initial.items()}
        self.bad_order = False
        self.order_timeout = False

    def check_query(self, command):
        answer = super().check_query(command)
        if command == "show firewall policy":
            if self.order_timeout:
                raise RuntimeError("Fortinet SSH reached its idle timeout")
            if self.bad_order:
                return answer.rsplit("end\n", 1)[0]
            if self.policies == self.initial and list(self.policies) == list(self.initial):
                return fixture("sequence")
        elif command == f'show {TABLE} "{FIRST}"' and self.policies.get(FIRST) == self.initial[FIRST]:
            return fixture("disabled")
        elif command.startswith(f'show {TABLE} "') and "entry is not found in table" in answer:
            return fixture("absent")
        return answer


def ask(label, op, key=FIRST, changes=None, *, impact=False):
    data = {"request_id": label, "table": TABLE, "key": key, "op": op, "changes": changes or {}}
    if impact:
        data["endpoint_impact"] = key
    return request(**data)


def approved(rt, device, req):
    snapshot, writes = device.snapshot(), list(device.applied_blocks)
    plan = execute.preview(rt, "lab", req)
    assert plan["result"] == "ready", plan
    assert device.snapshot() == snapshot and device.applied_blocks == writes
    return execute.apply(rt, "lab", req, expected_plan_sha256=plan["plan_sha256"])


def undo(rt, device, record):
    snapshot, writes = device.snapshot(), list(device.applied_blocks)
    preview = execute.preview_undo(rt, record["change_id"], "restore FIREWALL-POLICIES original order", issue=True)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == snapshot and device.applied_blocks == writes
    restored = execute.undo(rt, record["change_id"], "restore FIREWALL-POLICIES original order", preview["plan_sha256"])
    assert restored["result"] == "confirmed", restored


def test_delete_and_undo_restore_attributes_position_and_uuid(tmp_path):
    device = MeasuredPolicies()
    rt = runtime(tmp_path, device)
    original = device.snapshot()
    req = ask("firewall-policies-delete", "delete")
    with pytest.raises(Rejected) as refused:
        execute.apply(rt, "lab", req)
    assert refused.value.reason_codes == ["fortios_policy_preview_required"]
    assert not device.applied_blocks and not rt.store.records()
    record = approved(rt, device, req)
    assert record["result"] == "confirmed", record
    assert any(line.strip().rstrip('"').endswith(device.initial[FIRST]["uuid"])
               for line in record["plan"]["inverse"] if line.strip().startswith("set uuid "))
    assert record["plan"]["inverse_identity_changes"] == []
    assert list(device.policies) == [ANCHOR, SECOND]
    undo(rt, device, record)
    assert list(device.policies) == list(device.initial)
    assert device.policies[FIRST]["uuid"] == device.initial[FIRST]["uuid"]
    assert engine.verify(record["plan"], device.snapshot().encode(), expect="before")["result"] == "match"
    assert not device.actions and not device.stitches and not device.triggers
    assert engine.verify(record["plan"], original.encode(), expect="before")["result"] == "match"
    changed_uuid = device._uuid()
    device.policies[FIRST]["uuid"] = changed_uuid
    assert engine.verify(record["plan"], device.snapshot().encode(), expect="before")["result"] == "mismatch"
    assert engine.observed_state(record["plan"], device.policies[FIRST])["uuid"] == changed_uuid


def test_undo_create_after_another_policy_is_appended(tmp_path):
    device = MeasuredPolicies()
    device.policies.pop(FIRST)
    rt = runtime(tmp_path, device)
    created = approved(rt, device, ask("firewall-policies-create-first", "create", changes=BASE))
    assert created["result"] == "confirmed", created
    later = approved(rt, device, ask("firewall-policies-create-later", "create", NEW, BASE))
    assert later["result"] == "confirmed", later
    undo(rt, device, created)
    assert list(device.policies) == [ANCHOR, SECOND, NEW]


def test_undo_delete_when_manual_uuid_is_disabled(tmp_path):
    device = MeasuredPolicies()
    device.manual_policy_uuid = False
    rt = runtime(tmp_path, device)
    record = approved(rt, device, ask("firewall-policies-delete-auto-uuid", "delete"))
    assert record["result"] == "confirmed", record
    reason = "restore position with a FortiOS-assigned UUID"
    preview = execute.preview_undo(rt, record["change_id"], reason, issue=True)
    assert preview["result"] == "ready", preview
    assert not any("set uuid " in line for line in preview["commands"])
    restored = execute.undo(rt, record["change_id"], reason, preview["plan_sha256"])
    assert restored["result"] == "confirmed", restored
    assert list(device.policies) == list(device.initial)
    UUID = device.policies[FIRST]["uuid"]
    assert UUID != device.initial[FIRST]["uuid"]
    assert restored["warnings"] == [{"code": "uuid_changed", "original_uuid": device.initial[FIRST]["uuid"],
                                     "new_uuid": UUID}]
    assert not device.actions and not device.stitches and not device.triggers


def test_move_keeps_opaque_attributes_and_rejects_order_drift(tmp_path):
    device = MeasuredPolicies()
    original = dict(device.policies[FIRST], **{"srcaddr6": "literal-v6", "psksecret": "ENC test-secret-marker"})
    device.policies[FIRST] = original.copy()
    rt = runtime(tmp_path, device)
    req = ask("firewall-policies-move", "move", changes={"after": SECOND})
    preview = execute.preview(rt, "lab", req)
    assert preview["result"] == "ready", preview
    assert "test-secret-marker" not in str(preview)
    assert preview["policy_order"] == {"before": [FIRST, ANCHOR, SECOND], "after": [ANCHOR, SECOND, FIRST]}
    record = approved(rt, device, req)
    assert record["result"] == "confirmed", record
    assert list(device.policies) == [ANCHOR, SECOND, FIRST] and device.policies[FIRST] == original
    undo(rt, device, record)
    assert list(device.policies) == [FIRST, ANCHOR, SECOND]


@pytest.mark.parametrize("manual_uuid", [True, False])
def test_restore_after_failed_independent_readback(tmp_path, manual_uuid):
    device = MeasuredPolicies()
    device.manual_policy_uuid = manual_uuid
    rt = runtime(tmp_path, device)

    def fail_after_write(fake, lines):
        if lines[0] == "config firewall policy":
            fake.fail_next = 1

    device.on_apply = fail_after_write
    record = approved(rt, device, ask("firewall-policies-fail", "delete"))
    assert record["result"] == "reverted", record
    assert list(device.policies) == list(device.initial)
    assert engine.verify(record["plan"], device.snapshot().encode(), expect="before")["result"] == "match"
    original = device.initial[FIRST]["uuid"]
    restored = device.policies[FIRST]["uuid"]
    assert (restored == original) is manual_uuid
    if not manual_uuid:
        assert record["warnings"] == [{"code": "uuid_changed", "original_uuid": original, "new_uuid": restored}]
    assert not device.actions and not device.stitches and not device.triggers


def test_refuse_incomplete_policy_order_and_missing_anchor(tmp_path):
    device = MeasuredPolicies()
    rt = runtime(tmp_path, device)
    req = ask("firewall-policies-bad-order", "move", changes={"before": FIRST})
    assert execute.preview(rt, "lab", req)["reason_codes"] == ["fortios_policy_order_changed"]
    device.bad_order = True
    req = ask("firewall-policies-incomplete", "move", changes={"after": ANCHOR})
    assert execute.preview(rt, "lab", req)["reason_codes"] == ["fortios_policy_order_unreadable"]
    device.order_timeout = True
    assert execute.preview(rt, "lab", req)["reason_codes"] == ["fortios_policy_read_timeout"]
    assert not device.applied_blocks


def test_create_enabled_at_requested_position_with_profiles_in_one_apply(tmp_path):
    device = MeasuredPolicies()
    rt = runtime(tmp_path, device)
    changes = dict(BASE, before=SECOND, status="enable", nat="enable", name="netops-firewall-policies-published",
                   **{"utm-status": "enable", "ssl-ssh-profile": "certificate-inspection",
                      "webfilter-profile": "default"})
    request = ask("firewall-policies-publish", "create", NEW, changes)
    assert execute.preview(rt, "lab", request)["reason_codes"] == ["fortios_policy_impact_required"]
    record = approved(rt, device, ask("firewall-policies-publish-approved", "create", NEW, changes, impact=True))
    assert record["result"] == "confirmed", record
    commands = [line.strip() for line in record["plan"]["commands"]]
    assert commands.index('set status "disable"') < commands.index(f"move {NEW} before {SECOND}") < commands.index('set status "enable"')
    assert commands.index('set utm-status "enable"') < commands.index('set webfilter-profile "default"')
    assert list(device.policies) == [FIRST, ANCHOR, NEW, SECOND]
    measured = fortios.shown_object(fixture("enabled"), TABLE, NEW)
    assert engine.observed_state(record["plan"], measured) == record["plan"]["predicted"]["after"]
    assert len([block for block in device.applied_blocks if block[0] == "config firewall policy"]) == 1
    undo(rt, device, record)
    assert list(device.policies) == list(device.initial)


def test_rest_move_inverse_has_vendor_method_and_anchor():
    profile = profiles.find_profile("fortios", TABLE, "8.0.2 build0251")
    inverse = fortios.render_move(FIRST, ("before", ANCHOR))
    assert fortios.rest_inverse(profile, "move", FIRST, inverse, "192.0.2.1") == {
        "method": "put",
        "uri": f"192.0.2.1/api/v2/cmdb/firewall/policy/{FIRST}?action=move&before={ANCHOR}",
        "body": "",
    }


def test_foreign_order_change_invalidates_approved_plan():
    device = MeasuredPolicies()
    req = ask("firewall-policies-stale", "move", changes={"after": SECOND})
    before = device.snapshot()
    first = engine.build_plan("fortios", before.encode(), req)
    moved = prediction.snapshot_after(before, first)
    assert engine.verify(first, moved.encode())["result"] == "match"
    device.policies = {key: device.policies[key] for key in (ANCHOR, FIRST, SECOND)}
    second = engine.build_plan("fortios", device.snapshot().encode(), req)
    assert first["plan_sha256"] != second["plan_sha256"]


def test_first_policy_and_last_policy_removal_with_abbreviated_snapshot():
    device = MeasuredPolicies()
    snapshot = device.snapshot().split("config firewall policy\n", 1)[0]
    plan = engine.build_plan("fortios", snapshot.encode(), ask("firewall-policies-first", "create", changes=BASE))
    after = prediction.snapshot_after(snapshot, plan)
    assert engine.verify(plan, after.encode())["result"] == "match"
    measured_uuid = device.initial[FIRST]["uuid"]
    target_line = f'    edit "{FIRST}"\n'
    after = after.replace(target_line, target_line + f"        set uuid {measured_uuid}\n")
    deleted = engine.build_plan("fortios", after.encode(), ask("firewall-policies-last", "delete"))
    assert engine.verify(deleted, snapshot.encode())["result"] == "match"


def test_policy_reference_with_spaces_stays_one_fortios_name():
    device = MeasuredPolicies()
    device.addresses["netops-firewall-policies source"] = {"uuid": device._uuid()}
    request = ask("firewall-policies-spaced", "create", NEW, dict(BASE, srcaddr=["netops-firewall-policies source"]))
    plan = engine.build_plan("fortios", device.snapshot().encode(), request)
    assert '        set srcaddr "netops-firewall-policies source"' in plan["commands"]
    after = prediction.snapshot_after(device.snapshot(), plan)
    assert engine.verify(plan, after.encode())["result"] == "match"


@pytest.mark.parametrize("undo_activation", [False, True])
def test_enabling_a_staged_policy_ahead_of_protected_policy_is_refused(tmp_path, undo_activation):
    device = MeasuredPolicies()
    rt = runtime(tmp_path, device, protected={TABLE: [ANCHOR]})
    if undo_activation:
        device.policies[FIRST].pop("status")
        disabled = approved(rt, device, ask("firewall-policies-disable", "update", changes={"status": "disable"}, impact=True))
        assert disabled["result"] == "confirmed", disabled
        writes = list(device.applied_blocks)
        result = execute.preview_undo(rt, disabled["change_id"], "re-enable earlier policy", issue=True)
    else:
        writes = []
        result = execute.preview(rt, "lab", ask("firewall-policies-protected-publish", "update", changes={"status": "enable"}, impact=True))
    assert result["result"] == "rejected" and "protected policy" in " ".join(result["reasons"])
    assert device.applied_blocks == writes
