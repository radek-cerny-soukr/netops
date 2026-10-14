from __future__ import annotations

import json

import pytest
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request as change_request

from netops_admin import execute
from netops_admin.errors import Rejected
from netops_admin.state import Store

OLD, NEW = "b" * 32, "c" * 32


def audit_events(runtime):
    with open(runtime.config.audit_file, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def other_process(runtime):
    return Store(runtime.config.state_dir)


def blocked_runtime(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    runtime.store.block("lab", OLD, "foreign change")
    runtime.store.save_baseline("lab", "accounts-before")
    return runtime


def test_unblock_keeps_a_newer_block_written_between_its_read_and_its_removal(tmp_path):
    runtime = blocked_runtime(tmp_path)
    read = runtime.store.blocked

    def read_then_foreign_finish(device):
        seen = read(device)
        other = other_process(runtime)
        other.block(device, NEW, "revert-failed")
        other.save_baseline(device, "accounts-of-the-newer-apply")
        return seen

    runtime.store.blocked = read_then_foreign_finish
    with pytest.raises(Rejected, match="changed while it was being lifted") as caught:
        execute.unblock(runtime, "lab", "checked operation " + OLD)
    del runtime.store.blocked
    assert NEW in caught.value.reasons[0] and "nothing was removed" in caught.value.reasons[0]
    assert runtime.store.blocked("lab") == {"device": "lab", "change_id": NEW, "reason": "revert-failed"}
    assert runtime.store.baseline("lab") == "accounts-of-the-newer-apply"
    assert not [event for event in audit_events(runtime) if event.get("action") == "unblock"]


def test_unblock_is_refused_while_another_process_holds_the_device_lock(tmp_path):
    runtime = blocked_runtime(tmp_path)
    with other_process(runtime).lock("lab"):
        with pytest.raises(Rejected, match="another operation holds the device lock"):
            execute.unblock(runtime, "lab", "checked")
    assert runtime.store.blocked("lab")["change_id"] == OLD
    assert runtime.store.baseline("lab") == "accounts-before"


def test_unblock_removes_the_block_it_read_and_names_its_operation(tmp_path):
    runtime = blocked_runtime(tmp_path)
    assert execute.unblock(runtime, "lab", "checked operation " + OLD) is True
    assert runtime.store.blocked("lab") is None and runtime.store.baseline("lab") is None
    assert [event["change_id"] for event in audit_events(runtime) if event.get("action") == "unblock"] == [OLD]


def test_sequential_unblocks_lift_each_block_once(tmp_path):
    runtime = blocked_runtime(tmp_path)
    assert execute.unblock(runtime, "lab", "first") is True
    assert execute.unblock(runtime, "lab", "nothing left") is False
    other_process(runtime).block("lab", NEW, "revert-failed")
    assert runtime.store.blocked("lab")["change_id"] == NEW
    assert execute.unblock(runtime, "lab", "second") is True
    assert [event["change_id"] for event in audit_events(runtime) if event.get("action") == "unblock"] == [OLD, NEW]


def test_a_blocked_change_is_unblocked_and_the_next_change_runs(tmp_path):
    from enrollment_helpers import certify
    from test_gates_5_6 import at_change

    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    device.on_apply = at_change(lambda fake: fake.admin_comments.update({"netops-rw": "changed"}))
    first = execute.apply(runtime, "lab", change_request())
    assert first["result"] == "reverted"
    assert runtime.store.blocked("lab")["change_id"] == first["change_id"]
    device.on_apply = None
    assert execute.unblock(runtime, "lab", "investigated") is True
    assert runtime.store.blocked("lab") is None
    certify(runtime, device, "lab")
    assert execute.apply(runtime, "lab", change_request(key="second-host", request_id="req-second-1"))["result"] == "confirmed"


def finished(runtime, change_id, notification, **fields):
    record = {"change_id": change_id, "request_id": "req-" + change_id[:8], "device": "lab", "status": "finished",
              "result": "confirmed", "notification": notification, "steps": [], "created_at_epoch": 1.0}
    record.update(fields)
    runtime.store.save(record)
    return record


def test_a_waiver_cannot_slip_between_the_read_and_the_save_of_a_retry(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    change = "a" * 32
    finished(runtime, change, "failed")
    operator = make_runtime(tmp_path / "operator", FakeFortiOS())
    operator.store, operator.audit = Store(runtime.config.state_dir), runtime.audit
    seen = {}

    def notifier(record):
        with pytest.raises(Rejected, match="another operation holds the device lock"):
            execute.unblock(operator, "lab", "operator checked the channel")
        seen["during"] = other_process(runtime).operation(change)["notification"]
        return "failed"

    runtime.notifier = notifier
    assert execute.notify_retry(runtime, change)["notification"] == "failed"
    assert seen["during"] == "sending"
    assert runtime.store.operation(change)["notification"] == "failed"
    assert execute._undelivered(runtime, "lab") == [change]
    assert not [event for event in audit_events(runtime) if event.get("action") == "notification waived"]


def test_a_waived_notification_stays_waived_when_a_later_retry_fails(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    change = "e" * 32
    finished(runtime, change, "failed")
    assert execute.unblock(runtime, "lab", "operator checked the channel") is True
    runtime.notifier = lambda record: "failed"
    assert execute.notify_retry(runtime, change)["notification"] == "waived"
    assert runtime.store.operation(change)["notification"] == "waived"
    assert execute._undelivered(runtime, "lab") == []
    runtime.notifier = lambda record: "sent"
    assert execute.notify_retry(runtime, change)["notification"] == "sent"


def delivery_bench(tmp_path):
    import time

    device = FakeFortiOS()
    status = tmp_path / "export-status.json"
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 1, "oldest_pending_age_seconds": 1}))
    runtime = make_runtime(tmp_path, device, export_status=str(status))
    runtime.notifier = lambda record: "failed"
    record = execute.apply(runtime, "lab", change_request())
    assert record["notification"] == "failed" and record["audit_delivery"] == "pending"
    status.write_text(json.dumps({"updated_at": time.time() + 1, "pending": 0}))
    return runtime, record["change_id"]


def test_a_status_read_before_a_successful_retry_does_not_cause_a_second_send(tmp_path):
    runtime, change = delivery_bench(tmp_path)
    sends = []
    runtime.notifier = lambda record: sends.append(record["change_id"]) or "sent"
    stale = runtime.store.operation(change)
    assert execute.notify_retry(runtime, change)["notification"] == "sent"
    shown = execute.refresh_delivery(runtime, stale)
    assert shown["notification"] == "sent" and shown["audit_delivery"] == "acknowledged"
    saved = runtime.store.operation(change)
    assert saved["notification"] == "sent" and saved["audit_delivery"] == "acknowledged"
    assert execute.notify_retry(runtime, change)["notification"] == "sent"
    assert sends == [change]


def test_status_writes_nothing_while_another_operation_holds_the_device_lock(tmp_path):
    runtime, change = delivery_bench(tmp_path)
    path = tmp_path / "state" / "operations" / ("%s.json" % change)
    before = path.read_bytes()
    with other_process(runtime).lock("lab"):
        shown = execute.refresh_delivery(runtime, runtime.store.operation(change))
    assert shown["audit_delivery"] == "pending"
    assert path.read_bytes() == before
    assert execute.refresh_delivery(runtime, runtime.store.operation(change))["audit_delivery"] == "acknowledged"
    saved = runtime.store.operation(change)
    assert saved["audit_delivery"] == "acknowledged" and saved["notification"] == "failed"


def test_an_update_refuses_a_record_replaced_between_its_read_and_its_write(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    change = "d" * 32
    finished(runtime, change, "failed")

    def change_after_a_foreign_save(current):
        foreign = other_process(runtime).operation(change)
        foreign["notification"] = "sent"
        other_process(runtime).save(foreign)
        current["notification"] = "waived"
        return True

    with pytest.raises(Rejected, match="changed during the update"):
        runtime.store.update(change, change_after_a_foreign_save)
    assert runtime.store.operation(change)["notification"] == "sent"


def test_an_interrupted_send_stays_undelivered_and_is_sent_by_the_retry(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    change = "f" * 32
    finished(runtime, change, "sending")
    assert execute._undelivered(runtime, "lab") == [change]
    runtime.notifier = lambda record: "sent"
    assert execute.notify_retry(runtime, change)["notification"] == "sent"
    assert execute._undelivered(runtime, "lab") == []


def test_sequential_delivery_sends_once_and_status_only_acknowledges(tmp_path):
    runtime, change = delivery_bench(tmp_path)
    sends = []
    runtime.notifier = lambda record: sends.append(record["change_id"]) or "sent"
    assert execute.refresh_delivery(runtime, runtime.store.operation(change))["audit_delivery"] == "acknowledged"
    assert runtime.store.operation(change)["notification"] == "failed"
    assert execute.notify_retry(runtime, change)["notification"] == "sent"
    assert execute.notify_retry(runtime, change)["notification"] == "sent"
    assert sends == [change]
    deliveries = [(event["notification"], event["audit_delivery"]) for event in audit_events(runtime)
                  if event["event"] == "delivery"]
    assert deliveries == [("failed", "pending"), ("failed", "acknowledged"), ("sent", "acknowledged")]


ALIASED_TABLE = ("         Untagged\n"
                 "Port     /Tagged   VLAN Name(s)\n"
                 "-------- --------  ------------------------------------------------------------\n"
                 "InqBaseline\n"
                 "         Untagged  InqBase\n")
PLAIN_TABLE = ("         Untagged\n"
               "Port     /Tagged   VLAN Name(s)\n"
               "-------- --------  ------------------------------------------------------------\n"
               "2        Untagged  InqBase\n")
VLAN_MEMBERSHIP = "vlan-membership"


class CheckAccount:
    def __init__(self, port, table, detail):
        self.answers = {"show ports %s vlan" % port: table, "show ports %s information detail" % port: detail}
        self.queries = []

    def check_query(self, command):
        self.queries.append(command)
        return self.answers[command]


def detail(port, alias=None):
    return "Port:\t%s(%s):\n\tVirtual-router:\tVR-Default\n" % (port, alias) if alias else "Port:\t%s\n" % port


def observed(port, table, information):
    from netops_admin import exec_exos

    account = CheckAccount(port, table, information)
    return exec_exos.observe(account, {"table": VLAN_MEMBERSHIP, "key": port}), account.queries


def test_the_aliased_membership_table_of_the_issue_is_read_for_the_selected_port():
    state, queries = observed("1", ALIASED_TABLE, detail("1", "InqBaseline"))
    assert state == {"untagged": "InqBase", "tagged": ""}
    assert queries == ["show ports 1 vlan", "show ports 1 information detail"]


def test_a_port_without_a_display_string_is_read_from_its_number_alone():
    state, queries = observed("2", PLAIN_TABLE, detail("2"))
    assert state == {"untagged": "InqBase", "tagged": ""}
    assert queries == ["show ports 2 vlan"]


def test_a_short_display_string_in_the_port_column_is_read_for_the_selected_port():
    table = PLAIN_TABLE.replace("2        Untagged  InqBase\n", "Uplink   Untagged  users\n         Tagged    guest, staging\n")
    state, _queries = observed("2", table, detail("2", "Uplink"))
    assert state == {"untagged": "users", "tagged": "guest staging"}


def test_a_display_string_kept_at_20_characters_is_read_as_the_switch_reports_it():
    kept = "InqBaselineUplinkSW3-trunk"[:20]
    state, _queries = observed("1", ALIASED_TABLE.replace("InqBaseline\n", kept + "\n"), detail("1", kept))
    assert state == {"untagged": "InqBase", "tagged": ""}


@pytest.mark.parametrize(("port", "table", "information", "reason"), [
    ("1", ALIASED_TABLE, detail("1", "Uplink"), "another name than the display string"),
    ("1", ALIASED_TABLE, detail("1"), "another name than the display string"),
    ("1", ALIASED_TABLE, detail("2", "InqBaseline"), "names another port"),
    ("1", ALIASED_TABLE, "%% Invalid port number detected.\n", "another name than the display string"),
    ("1", ALIASED_TABLE.replace("InqBaseline\n", "InqBaselineUplinkSW3\n"), detail("1", "InqBaselineUplinkSW3-trunk"),
     "another name than the display string"),
    ("1", ALIASED_TABLE.replace("InqBaseline\n", "InqBaseline\n         Untagged  InqBase\nOther\n"),
     detail("1", "InqBaseline"), "another name than the display string"),
    ("1", PLAIN_TABLE.replace("2        ", "3        "), detail("1"), "returned another port"),
    ("1", ALIASED_TABLE.replace("InqBaseline\n", "2\n"), detail("1", "2"), "returned another port"),
], ids=["other-display-string", "no-display-string", "detail-of-another-port", "detail-unreadable",
        "truncated-name-is-not-a-prefix-match", "second-named-block", "other-port-number",
        "display-string-equal-to-another-port-number"])
def test_another_or_ambiguous_port_in_the_membership_answer_is_refused(port, table, information, reason):
    with pytest.raises(Rejected, match=reason):
        observed(port, table, information)


def aliased_switch(alias):
    from fake_020 import ExosMembership

    class AliasedMembership(ExosMembership):
        def check_query(self, command):
            text = super().check_query(command)
            if command == "show ports 10 vlan" and "10" in self.port_strings:
                text = text.replace("10 Untagged", "%s\n         Untagged" % self.port_strings["10"])
            return text

    switch = AliasedMembership()
    switch.port_strings["10"] = alias[:20]
    return switch


def membership_runtime(tmp_path, switch):
    from dataclasses import replace

    from enrollment_helpers import certify
    from test_execute_exos import make_runtime as make_exos_runtime

    runtime = make_exos_runtime(tmp_path, switch)
    policy = {"version": 1, "platform": "exos",
              "port_vlans": {"10": {"tagged": ["guest", "users", "staging"], "untagged": ["users", "staging", "guest"]}},
              "protected_ports": ["12", "13"], "management_vlans": ["Mgmt"]}
    runtime.config = replace(runtime.config, devices={"sw": replace(runtime.config.devices["sw"], audit_policy=policy)})
    return certify(runtime, switch, "sw")


def membership_request(request_id="req-membership-1"):
    from test_operations_020 import request

    return request(VLAN_MEMBERSHIP, "10", {"untagged": "staging"}, request_id=request_id)


def test_preview_and_apply_read_the_membership_of_a_port_with_a_display_string(tmp_path):
    switch = aliased_switch("InqBaseline")
    runtime = membership_runtime(tmp_path, switch)
    preview = execute.preview(runtime, "sw", membership_request())
    assert preview["result"] == "ready", preview["reasons"]
    record = execute.apply(runtime, "sw", membership_request())
    assert record["result"] == "confirmed"
    assert switch.memberships["10"]["untagged"] == "staging" and switch.port_strings["10"] == "InqBaseline"


def test_a_display_string_the_switch_kept_at_20_characters_does_not_stop_the_change(tmp_path):
    switch = aliased_switch("InqBaselineUplinkSW3-trunk")
    runtime = membership_runtime(tmp_path, switch)
    assert execute.apply(runtime, "sw", membership_request())["result"] == "confirmed"


def test_a_membership_answer_for_another_name_is_refused_with_its_own_reason(tmp_path):
    switch = aliased_switch("InqBaseline")
    runtime = membership_runtime(tmp_path, switch)
    switch.check_override = {"10": "Uplink"}
    preview = execute.preview(runtime, "sw", membership_request())
    assert preview["result"] == "rejected"
    assert "another name than the display string" in preview["reasons"][0]
    assert "could not read the object" not in preview["reasons"][0]
    assert not switch.applied_blocks


def test_a_port_without_a_display_string_still_changes_as_before(tmp_path):
    switch = aliased_switch("InqBaseline")
    del switch.port_strings["10"]
    runtime = membership_runtime(tmp_path, switch)
    assert execute.apply(runtime, "sw", membership_request())["result"] == "confirmed"
    assert switch.memberships["10"]["untagged"] == "staging"


REQUIRED = "export status does not name the audit file (export_status_require_audit_file is enabled)"
OTHER_AUDIT_FILE = "/var/lib/netops-admin-audit/audit.jsonl"


def config_file(tmp_path, **top):
    body = {"platform": "fortios", "address": "192.0.2.1", "host_key_fingerprint": "SHA256:" + "A" * 43,
            "vault": "/nonexistent/vault.json", "credential": "rw", "check_credential": "ro"}
    document = {"version": 1, "state_dir": str(tmp_path / "state"), "audit_file": str(tmp_path / "audit.jsonl"),
                "devices": {"lab": body}}
    document.update(top)
    path = tmp_path / "admin.json"
    path.write_text(json.dumps(document))
    return path


def test_the_audit_file_requirement_is_off_unless_configured(tmp_path):
    from netops_admin.config import load_config

    assert load_config(config_file(tmp_path)).export_status_require_audit_file is False
    assert load_config(config_file(tmp_path, export_status_require_audit_file=False)).export_status_require_audit_file is False
    assert load_config(config_file(tmp_path, export_status_require_audit_file=True)).export_status_require_audit_file is True


@pytest.mark.parametrize("value", ["true", 1, 0, None, [], {}])
def test_an_audit_file_requirement_that_is_not_a_boolean_is_a_configuration_error(tmp_path, value):
    from netops_admin.config import load_config

    with pytest.raises(Rejected, match="export_status_require_audit_file must be true or false"):
        load_config(config_file(tmp_path, export_status_require_audit_file=value))


def export_status(tmp_path, **fields):
    import time

    path = tmp_path / "export-status.json"
    path.write_text(json.dumps(dict({"updated_at": time.time(), "pending": 0}, **fields)))
    return str(path)


@pytest.mark.parametrize(("require", "named", "expected"), [
    (False, None, ("acknowledged", "the export status does not name the audit file")),
    (False, "own", ("acknowledged", None)),
    (False, "other", ("blocked", "the export status covers another audit file")),
    (True, None, ("blocked", REQUIRED)),
    (True, "own", ("acknowledged", None)),
    (True, "other", ("blocked", "the export status covers another audit file")),
], ids=["compatible-unnamed", "compatible-own", "compatible-other", "required-unnamed", "required-own", "required-other"])
def test_the_export_status_is_judged_by_the_audit_file_requirement(tmp_path, require, named, expected):
    from netops_admin import audit
    from netops_admin.config import DEFAULT_LIMITS

    own = str(tmp_path / "audit.jsonl")
    fields = {} if named is None else {"audit_file": own if named == "own" else OTHER_AUDIT_FILE}
    assert audit.export_state(export_status(tmp_path, **fields), DEFAULT_LIMITS, audit_file=own,
                              require_audit_file=require) == expected


def requiring_runtime(tmp_path, device, require=True, **fields):
    import dataclasses

    from enrollment_helpers import certify

    runtime = make_runtime(tmp_path, device)
    status = export_status(tmp_path, **fields)
    runtime.config = dataclasses.replace(runtime.config, export_status_file=status,
                                         export_status_require_audit_file=require)
    return certify(runtime, device, "lab")


def test_switching_the_audit_file_requirement_keeps_the_enrollment_binding(tmp_path):
    import dataclasses

    from netops_admin import enrollment

    config = make_runtime(tmp_path, FakeFortiOS()).config
    device = config.devices["lab"]
    strict = dataclasses.replace(config, export_status_require_audit_file=True)
    assert enrollment.binding(device, "accounts", "8.0.0", config) == enrollment.binding(device, "accounts", "8.0.0", strict)


def test_an_unnamed_export_status_is_refused_before_any_change_when_the_audit_file_is_required(tmp_path):
    device = FakeFortiOS()
    runtime = requiring_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", change_request())
    assert caught.value.reasons == ["audit export is blocked: " + REQUIRED]
    assert device.applied_blocks == []


def test_an_export_status_naming_another_audit_file_is_still_refused_when_the_audit_file_is_required(tmp_path):
    device = FakeFortiOS()
    runtime = requiring_runtime(tmp_path, device, audit_file=OTHER_AUDIT_FILE)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", change_request())
    assert caught.value.reasons == ["audit export is blocked: the export status covers another audit file"]
    assert device.applied_blocks == []


def test_an_export_status_naming_the_audit_file_is_accepted_when_the_audit_file_is_required(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    runtime = requiring_runtime(tmp_path, device, audit_file=runtime.config.audit_file)
    record = execute.apply(runtime, "lab", change_request())
    assert record["result"] == "confirmed" and record["audit_delivery"] == "pending"


def test_an_unnamed_export_status_is_still_accepted_by_default(tmp_path):
    device = FakeFortiOS()
    runtime = requiring_runtime(tmp_path, device, require=False)
    assert execute.apply(runtime, "lab", change_request())["result"] == "confirmed"


@pytest.mark.parametrize("named", ["unnamed", "other"])
def test_the_command_line_refuses_both_forms_the_same_way(tmp_path, capsys, named):
    from conftest import request_bytes
    from netops_admin import cli

    status = export_status(tmp_path, **({} if named == "unnamed" else {"audit_file": OTHER_AUDIT_FILE}))
    path = config_file(tmp_path, export_status_file=status, export_status_require_audit_file=True)
    request = tmp_path / "request.json"
    request.write_bytes(request_bytes())
    code = cli.main(["apply", "--config", str(path), "--device", "lab", "--request", str(request)])
    answer = json.loads(capsys.readouterr().out)
    why = REQUIRED if named == "unnamed" else "the export status covers another audit file"
    assert code == cli.EXIT_REJECTED
    assert answer == {"result": "rejected", "reasons": ["audit export is blocked: " + why]}


@pytest.mark.parametrize("require", [False, True])
def test_doctor_shows_the_audit_file_requirement(tmp_path, require):
    from netops_admin import readiness

    runtime = requiring_runtime(tmp_path, FakeFortiOS(), require=require)
    report = readiness.doctor(runtime, "lab")
    assert report["configuration"] == {"export_status_require_audit_file": require}
    export = [(item["status"], item["detail"]) for item in report["checks"] if item["check"] == "audit export"][0]
    assert export == ((readiness.REFUSED, REQUIRED) if require
                      else (readiness.OK, "acknowledged; the export status does not name the audit file"))


@pytest.mark.parametrize("require", [False, True])
def test_admin_status_carries_the_audit_file_requirement(tmp_path, monkeypatch, require):
    import dataclasses

    from test_mcp_server import arguments, call
    from netops_admin import mcp_server

    runtime = make_runtime(tmp_path, FakeFortiOS())
    monkeypatch.setattr(mcp_server, "build_runtime", lambda config: runtime)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    assert call("admin_apply", arguments())["result"] == "confirmed"
    runtime.config = dataclasses.replace(runtime.config, export_status_require_audit_file=require)
    status = call("admin_status", {"request_id": "req-mcp-0001"})
    assert status["result"] == "confirmed"
    assert status["configuration"] == {"export_status_require_audit_file": require}
    unknown = call("admin_status", {"change_id": "0" * 32})
    assert unknown["result"] == "unknown-operation"
    assert unknown["configuration"] == {"export_status_require_audit_file": require}


def identities(events, **match):
    return [(event["event"], event.get("action"), event.get("device", "missing"), event.get("change_id", "missing"))
            for event in events if all(event.get(name) == value for name, value in match.items())]


def test_every_audit_event_of_a_change_names_its_device_and_its_change(tmp_path):
    runtime, change = delivery_bench(tmp_path)
    assert execute.refresh_delivery(runtime, runtime.store.operation(change))["audit_delivery"] == "acknowledged"
    runtime.notifier = lambda record: "sent"
    assert execute.notify_retry(runtime, change)["notification"] == "sent"
    events = audit_events(runtime)
    assert {event["event"] for event in events} == {"start", "step", "result", "delivery"}
    assert [(event["notification"], event["audit_delivery"]) for event in events if event["event"] == "delivery"] == [
        ("failed", "pending"), ("failed", "acknowledged"), ("sent", "acknowledged")]
    assert {identity[2:] for identity in identities(events)} == {("lab", change)}


def test_an_administrator_table_block_is_audited_with_its_device_and_without_a_change(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = execute.apply(runtime, "lab", change_request())
    assert first["result"] == "confirmed"
    device.admin_comments["netops-rw"] = "changed by someone"
    with pytest.raises(Rejected, match="changed since the last operation"):
        execute.apply(runtime, "lab", change_request(key="second-host", request_id="req-second-1"))
    assert runtime.store.blocked("lab") == {"device": "lab", "change_id": None, "reason": "administrator table"}
    assert identities(audit_events(runtime), event="administrative") == [
        ("administrative", "blocked: administrator table", "lab", None)]


def test_unblock_audits_the_lifted_block_and_each_waived_notification_with_device_and_change(tmp_path):
    runtime = blocked_runtime(tmp_path)
    undelivered = "a" * 32
    finished(runtime, undelivered, "failed")
    assert execute.unblock(runtime, "lab", "checked operation " + OLD) is True
    assert runtime.store.blocked("lab") is None
    assert runtime.store.operation(undelivered)["notification"] == "waived"
    assert identities(audit_events(runtime), event="administrative") == [
        ("administrative", "unblock", "lab", OLD), ("administrative", "notification waived", "lab", undelivered)]
