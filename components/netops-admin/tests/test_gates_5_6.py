from __future__ import annotations

import pytest
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request, steps
from test_execute_exos import make_runtime as make_exos_runtime
from test_execute_exos import request as exos_request

from netops_admin import audit_gate, exos, execute, fortios
from netops_admin.errors import Rejected


def at_change(action):
    def hook(fake, lines):
        if len(fake.applied_blocks) == 2:
            action(fake)
    return hook


def test_check_account_that_cannot_read_refuses_before_any_mutation(tmp_path):
    device = FakeFortiOS()
    device.check_unreadable = True
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert "check account could not read" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_check_account_seeing_another_state_refuses_before_any_mutation(tmp_path):
    device = FakeFortiOS()
    device.check_override = {"spare-host": {"subnet": "192.0.2.99 255.255.255.255", "comment": "unused"}}
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab",
                      request(op="update", key="spare-host", changes={"comment": "x"}))
    assert "another state than the snapshot" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_check_account_seeing_another_result_reverts(tmp_path):
    device = FakeFortiOS()
    device.on_apply = at_change(lambda fake: setattr(fake, "check_override", {"new-host": None}))
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch"
    assert "new-host" not in device.addresses and not device.stitches


def test_check_account_lost_after_the_change_reverts(tmp_path):
    device = FakeFortiOS()
    device.on_apply = at_change(lambda fake: setattr(fake, "check_unreadable", True))
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable"


def test_both_gates_pass_on_a_normal_change(tmp_path):
    record = execute.apply(make_runtime(tmp_path, FakeFortiOS()), "lab", request())
    assert record["result"] == "confirmed"
    assert steps(record).index("audit_passed") < steps(record).index("check_identity_passed") \
        < steps(record).index("confirm_start")


def test_new_audit_finding_reverts(tmp_path, monkeypatch):
    original = audit_gate.new_blocking
    calls = []
    def fail_after(*args):
        calls.append(None)
        return original(*args) if len(calls) == 1 else ["fortios-dangling-reference"]
    monkeypatch.setattr(audit_gate, "new_blocking", fail_after)
    device = FakeFortiOS()
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted" and record["reason"] == "audit finding"
    assert record["audit_findings"] == ["fortios-dangling-reference"]
    assert "new-host" not in device.addresses


def test_audit_that_cannot_evaluate_after_the_change_reverts(tmp_path, monkeypatch):
    original = audit_gate.new_blocking
    calls = []
    def broken(*args):
        calls.append(None)
        if len(calls) > 1:
            raise RuntimeError("rule failed")
        return original(*args)

    monkeypatch.setattr(audit_gate, "new_blocking", broken)
    record = execute.apply(make_runtime(tmp_path, FakeFortiOS()), "lab", request())
    assert record["result"] == "reverted" and record["reason"] == "audit unavailable"


def test_audit_that_cannot_evaluate_before_the_change_refuses(tmp_path, monkeypatch):
    def broken(*args):
        raise RuntimeError("rule failed")

    monkeypatch.setattr(audit_gate, "findings", broken)
    device = FakeFortiOS()
    with pytest.raises(Rejected) as caught:
        execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert "auditor could not evaluate" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_exos_check_account_is_asked_and_a_mismatch_reverts(tmp_path):
    device = FakeExos()
    device.on_apply = at_change(lambda fake: setattr(fake, "check_override", {"guest": {"tag": "3998"}}))
    record = execute.apply(make_exos_runtime(tmp_path, device), "sw", exos_request())
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch"
    assert "guest" not in device.vlans and not device.profiles and not device.timers


def test_real_auditor_rules_report_a_new_finding(exos_snapshot):
    before_text = exos_snapshot.decode("utf-8")
    before = audit_gate.findings("exos", before_text, "sw")
    after_text = before_text + "#\n# Module snmpMaster configuration.\n#\nconfigure snmp add community readonly public\n"
    assert audit_gate.new_blocking("exos", set(before), before_text, "sw") == []
    assert audit_gate.new_blocking("exos", set(before), after_text, "sw")


def test_fortios_answer_of_the_check_account_is_read():
    answer = ('FortiGate-60F $ config firewall address\n    edit "web"\n        set uuid 1\n'
              '        set comment "two words"\n        set subnet 192.0.2.10 255.255.255.255\n    next\nend\n')
    assert fortios.shown_object(answer, "firewall address", "web") == {
        "uuid": "1", "comment": "two words", "subnet": "192.0.2.10 255.255.255.255"}
    assert fortios.shown_object("entry is not found in table\n", "firewall address", "web") is None
    with pytest.raises(Rejected):
        fortios.shown_object("Command fail. Return code -37\n", "firewall address", "web")


def test_exos_answer_of_the_check_account_is_read():
    present = ("VLAN Interface with name guest created by user\n"
               "    Admin State:\t Enabled     Tagging:\t802.1Q Tag 30 \n    Description:\t None\n")
    assert exos.shown_vlan(present, "guest") == {"tag": "30"}
    described = present.replace("Description:\t None", "Description:\t Management VLAN ")
    assert exos.shown_vlan(described, "guest") == {"tag": "30", "description": "Management VLAN"}
    absent = "               ^\n%% Invalid numeric list detected at '^' marker.\n"
    assert exos.shown_vlan(absent, "guest") is None
    with pytest.raises(Rejected):
        exos.shown_vlan("This user does not have permissions for this command.\n", "guest")
    with pytest.raises(Rejected):
        exos.shown_vlan(present, "other")


def test_admin_entry_changed_since_the_last_operation_blocks(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"
    device.admin_comments["netops-rw"] = "changed by someone"
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(key="second-host", request_id="req-second-1"))
    assert "changed since the last operation" in caught.value.reasons[0]
    assert len(device.applied_blocks) == blocks
    assert runtime.store.blocked("lab")["reason"] == "administrator table"
    assert execute.unblock(runtime, "lab", "investigated the comment change")
    from enrollment_helpers import certify
    certify(runtime, device, "lab")
    assert execute.apply(runtime, "lab", request(key="second-host", request_id="req-second-2"))["result"] == "confirmed"


def test_admin_entry_changed_during_the_change_reverts_and_blocks(tmp_path):
    device = FakeFortiOS()
    device.on_apply = at_change(lambda fake: fake.admin_comments.update({"netops-rw": "changed"}))
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "reverted" and record["reason"] == "administrator table"
    assert runtime.store.blocked("lab") is not None


def test_configured_check_account_may_be_visible(tmp_path):
    from dataclasses import replace

    device = FakeFortiOS()
    device.admins.append("netops-check")
    runtime = make_runtime(tmp_path, device)
    config = runtime.config
    lab = replace(config.devices["lab"], accounts=("netops-check", "netops-rw"))
    runtime.config = replace(config, devices={"lab": lab})
    from enrollment_helpers import certify
    certify(runtime, device, "lab")
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"


def test_exos_account_hash_changed_since_the_last_operation_blocks(tmp_path):
    device = FakeExos()
    runtime = make_exos_runtime(tmp_path, device)
    assert execute.apply(runtime, "sw", exos_request())["result"] == "confirmed"
    device.account_hashes["netops-rw"] = "$5$new$hash"
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "sw", exos_request(key="guest2", changes={"tag": 3997}, request_id="req-second-1"))
    assert "changed since the last operation" in caught.value.reasons[0]


def test_undelivered_notification_stops_the_next_change_on_the_device(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    runtime.notifier = lambda record: "failed"
    first = execute.apply(runtime, "lab", request())
    assert first["result"] == "confirmed" and first["notification"] == "failed"
    blocks = len(device.applied_blocks)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(key="second-host", request_id="req-second-1"))
    assert "was not delivered" in caught.value.reasons[0]
    assert len(device.applied_blocks) == blocks
    runtime.notifier = lambda record: "sent"
    assert execute.notify_retry(runtime, first["change_id"])["notification"] == "sent"
    assert execute.apply(runtime, "lab", request(key="second-host", request_id="req-second-2"))["result"] == "confirmed"


def test_a_person_can_waive_an_undeliverable_notification(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    runtime.notifier = lambda record: "failed"
    first = execute.apply(runtime, "lab", request())
    assert execute.unblock(runtime, "lab", "the notification channel is down, the change was reviewed")
    assert runtime.store.operation(first["change_id"])["notification"] == "waived"
    events = [line for line in (tmp_path / "audit" / "audit.jsonl").read_text().splitlines()
              if "notification waived" in line]
    assert len(events) == 1
    runtime.notifier = lambda record: "sent"
    assert execute.apply(runtime, "lab", request(key="second-host", request_id="req-second-1"))["result"] == "confirmed"


def test_foreign_admin_sessions_are_recorded_and_notified(tmp_path):
    from netops_admin import notify

    device = FakeFortiOS()
    device.foreign_session_users = ["ai-login", "admin"]
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "confirmed" and record["foreign_sessions"] == 2
    assert "other administrator sessions were active: 2" in notify.message(record)[1]
    quiet = execute.apply(make_runtime(tmp_path / "quiet", FakeFortiOS()), "lab", request())
    assert quiet["foreign_sessions"] == 0
    assert "other administrator sessions" not in notify.message(quiet)[1]


def test_exos_sessions_other_than_the_own_are_counted(tmp_path):
    device = FakeExos()
    device.foreign_session_users = ["ai-login"]
    record = execute.apply(make_exos_runtime(tmp_path, device), "sw", exos_request())
    assert record["foreign_sessions"] == 1


def test_session_lists_as_the_devices_print_them():
    fortios_list = ("FortiGate-60F $ username             local          device                         vdom     profile"
                    "               remote                 started     \n"
                    "Fortimanager_Access  fgc            N/A                            root     super_admin"
                    "           :0                     2026-09-23 11:12:19\n"
                    "netops-rw            ssh            wan1:192.0.2.1:22        root     netops-rw"
                    "             192.0.2.9:40924    2026-09-23 17:17:31\n\nFortiGate-60F $ ")
    assert fortios.foreign_sessions(fortios_list, {"netops-rw", "netops-check"}) == 0
    assert fortios.foreign_sessions(fortios_list, {"netops-check"}) == 1
    exos_list = ("                                                                    CLI \n"
                 "    #       Login Time               User     Type    Auth          Auth Location\n"
                 "=======================================================================================\n"
                 " 470        Wed Sep 23 10:11:01 2026 ai-login ssh2    sshKey        dis  192.0.2.8  \n"
                 "*753        Wed Sep 23 17:18:01 2026 netop .. ssh2    sshKey        dis  192.0.2.9  \n")
    assert exos.foreign_sessions(exos_list) == 1
    with pytest.raises(Rejected):
        exos.foreign_sessions("This user does not have permissions for this command.\n")
