from __future__ import annotations

import json
import re

import pytest
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request
from test_execute_exos import make_runtime as make_exos_runtime, request as exos_request
from test_schema_plan import TEXT as SCHEMA_TEXT, op
from test_schema_runtime import request as schema_request, setup as schema_setup

from netops_admin import audit_gate, execute, schema_runtime

DEFAULT_ADMIN = "fortios.mgmt.default-admin-account"
UNPROVEN = "admin-visibility-unproven"
WRITE_VIEW = ['    edit "netops-rw"', '        set accprofile "netops-rw"', '        set vdom "root"', "    next"]
SUPER_VIEW = ['    edit "super-example"', '        set accprofile "super_admin"',
              '        set trusthost1 192.0.2.0 255.255.255.0', "    next"]
ADMIN_BLOCK = re.compile(r"config system admin\n.*?\nend\n", re.S)
NO_TRUSTHOST = "fortios.mgmt.admin-no-trusthost"


def live_admin(name, second=False, key=False):
    lines = ['    edit "%s"' % name, '        set vdom "root"', "        set trusthost1 192.0.2.0 255.255.255.0"]
    lines += ["        set trusthost2 198.51.100.0 255.255.255.0"] if second else []
    lines += ['        set accprofile "%s"' % name, '        set comments "synthetic view"']
    lines += ['        set ssh-public-key1 "ssh-ed25519 MASKED"'] if key else []
    return lines + ["        set password ENC MASKED", "    next"]


LIVE_RO_VIEW = live_admin("netops-ro", second=True)
LIVE_RW_VIEW = (live_admin("netops-rw", key=True) + live_admin("netops-check", key=True)
                + live_admin("example-ro", second=True, key=True) + live_admin("example-rw", second=True))


class WriteAccountView(FakeFortiOS):
    def __init__(self, admins=WRITE_VIEW):
        super().__init__()
        self.view = list(admins)

    def snapshot(self):
        text = ADMIN_BLOCK.sub("", super().snapshot(), count=1)
        block = "" if self.view is None else "\n".join(["config system admin", *self.view, "end"]) + "\n"
        return text.replace("end\nconfig firewall address\n", "end\n" + block + "config firewall address\n", 1)


def test_the_write_account_view_is_tolerated_and_reported(tmp_path):
    device = WriteAccountView()
    runtime = make_runtime(tmp_path, device)
    answer = execute.preview(runtime, "lab", request())
    assert answer["result"] != "rejected"
    assert answer["audit_unevaluated"][DEFAULT_ADMIN] == UNPROVEN
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "confirmed"
    assert tuple(record["audit_before"]["not-evaluated:" + DEFAULT_ADMIN]) == (DEFAULT_ADMIN, "not-evaluated", UNPROVEN)
    passed = [step for step in record["steps"] if step["step"] == "audit_passed"]
    assert passed and "not evaluated before and after: " in passed[0]["detail"]


def gate_texts():
    device = WriteAccountView()
    write_view = device.snapshot()
    device.view = WRITE_VIEW + SUPER_VIEW
    super_view = device.snapshot()
    device.view = None
    return write_view, super_view, device.snapshot()


def test_the_gate_tolerates_only_the_same_reason():
    write_view, super_view, no_admins = gate_texts()
    before = audit_gate.baseline("fortios", write_view, "lab")
    assert audit_gate.unevaluated(before)[DEFAULT_ADMIN] == UNPROVEN
    assert "not evaluated before and after: " in audit_gate.summary(before)
    audit_gate.evaluate("fortios", write_view, None, "firewall address", before)
    assert audit_gate.new_blocking("fortios", before, write_view, "lab") == []
    with pytest.raises(audit_gate.Incomplete) as changed:
        audit_gate.evaluate("fortios", no_admins, None, "firewall address", before)
    assert "section-missing: system admin" in changed.value.reasons[0]
    evaluated = audit_gate.baseline("fortios", super_view, "lab")
    assert DEFAULT_ADMIN not in audit_gate.unevaluated(evaluated)
    with pytest.raises(audit_gate.Incomplete) as new:
        audit_gate.new_blocking("fortios", evaluated, write_view, "lab")
    assert UNPROVEN in new.value.reasons[0]


def test_without_a_baseline_nothing_is_tolerated():
    write_view, _super_view, _none = gate_texts()
    with pytest.raises(audit_gate.Incomplete):
        audit_gate.findings("fortios", write_view, "lab")
    with pytest.raises(audit_gate.Incomplete):
        audit_gate.evaluate("fortios", write_view, None, "firewall address", {})


def test_required_management_rules_are_never_tolerated():
    write_view, _super_view, _none = gate_texts()
    policy = {"version": 1, "platform": "fortios", "required_rules": ["address-policy"]}
    with pytest.raises(audit_gate.Incomplete):
        audit_gate.baseline("fortios", write_view, "lab", policy)


def test_the_predicted_switch_configuration_keeps_every_module_of_the_snapshot(tmp_path):
    answer = execute.preview(make_exos_runtime(tmp_path, FakeExos()), "sw", exos_request())
    assert (answer["result"], answer["reasons"], answer["audit_unevaluated"]) == ("ready", [], {})


def test_the_schema_audit_tolerates_only_what_its_baseline_recorded(tmp_path, monkeypatch):
    _lib, device = schema_setup(tmp_path)
    plan = schema_runtime.build(device, schema_request([op()]), SCHEMA_TEXT)
    rule = json.dumps(["root", DEFAULT_ADMIN], separators=(",", ":"))
    reason = ["section-missing: system admin"]
    monkeypatch.setattr(schema_runtime.scoped_fortios, "run",
                        lambda *_args: ([], {rule: (audit_gate.NOT_EVALUATED, reason[0])}))
    with pytest.raises(audit_gate.Incomplete):
        schema_runtime.audit_snapshot(plan, SCHEMA_TEXT, None)
    before, _coverage = schema_runtime.audit_snapshot(plan, SCHEMA_TEXT, None, None, audit_gate.BASELINE)
    assert audit_gate.unevaluated(before) == {rule: reason[0]}
    assert schema_runtime.after_audit(plan, before, SCHEMA_TEXT, None)[0] == []
    reason[0] = UNPROVEN
    with pytest.raises(audit_gate.Incomplete):
        schema_runtime.after_audit(plan, before, SCHEMA_TEXT, None)


@pytest.mark.parametrize("view", [LIVE_RO_VIEW, LIVE_RW_VIEW], ids=["read-account", "write-account"])
def test_the_live_test_account_views_pass_the_preview_as_unproven(tmp_path, view):
    before = audit_gate.baseline("fortios", WriteAccountView(view).snapshot(), "lab")
    assert audit_gate.unevaluated(before) == {DEFAULT_ADMIN: UNPROVEN, NO_TRUSTHOST: UNPROVEN}
    assert not any(value[0] in (DEFAULT_ADMIN, NO_TRUSTHOST) for key, value in before.items()
                   if not key.startswith(audit_gate.UNEVALUATED))
    answer = execute.preview(make_runtime(tmp_path, WriteAccountView(view)), "lab", request())
    assert (answer["result"], answer["reasons"]) == ("ready", [])
    assert answer["audit_unevaluated"] == {DEFAULT_ADMIN: UNPROVEN, NO_TRUSTHOST: UNPROVEN}
