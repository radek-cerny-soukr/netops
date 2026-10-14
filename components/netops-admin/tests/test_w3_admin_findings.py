from __future__ import annotations

import importlib.util
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_fortios import FakeFortiOS
from test_access import Shell, device_access
from test_execute import make_runtime, request

from netops_admin import engine, exec_fortios, execute, fortios, schema_runtime
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile
from netops_admin.request import parse_request
from netops_admin.state import Store

HEADER = "#config-version=FGT60F-7.6.7-FW-build3704-250101:opmode=0:vdom=0:user=netops\n"
ONE_OBJECT = '    edit "web-01"\n        set subnet 192.0.2.1 255.255.255.255\n        set comment "a"\n    next\n'
REPEATED = {
    "set": '    edit "web-01"\n        set subnet 192.0.2.1 255.255.255.255\n        set comment "a"\n'
           '        set comment "b"\n    next\n',
    "set-unset": '    edit "web-01"\n        set subnet 192.0.2.1 255.255.255.255\n        set comment "a"\n'
                 '        unset comment\n    next\n',
    "unset-set": '    edit "web-01"\n        set subnet 192.0.2.1 255.255.255.255\n        unset comment\n'
                 '        set comment "a"\n    next\n',
    "edit": '    edit "web-01"\n        set subnet 192.0.2.1 255.255.255.255\n    next\n'
            '    edit "web-01"\n        set comment "a"\n    next\n',
}
OP_FIELDS = {"update": {"changes": {"comment": "new"}}, "delete": {"changes": {}}}


def address_snapshot(body: str) -> bytes:
    return (HEADER + 'config system global\n    set hostname "fw"\nend\nconfig firewall address\n' + body
            + "end\n").encode("utf-8")


def plan_on(body: str, **fields):
    fields.setdefault("key", "web-01")
    return engine.build_plan("fortios", address_snapshot(body), parse_request(request_bytes(**fields)))


@pytest.mark.parametrize("op", ["update", "delete"])
@pytest.mark.parametrize("shape", sorted(REPEATED))
def test_a_repeated_line_or_block_of_the_object_refuses_the_plan(shape, op):
    with pytest.raises(Rejected) as caught:
        plan_on(REPEATED[shape], op=op, **OP_FIELDS[op])
    assert any("repeated" in reason for reason in caught.value.reasons), caught.value.reasons
    assert plan_on(ONE_OBJECT, op=op, **OP_FIELDS[op])["predicted"]["before"] == {
        "subnet": "192.0.2.1 255.255.255.255", "comment": "a"}


def test_a_repetition_in_another_object_does_not_refuse_the_plan():
    body = ONE_OBJECT + REPEATED["set"].replace("web-01", "web-02")
    assert plan_on(body, op="update", changes={"comment": "new"})["predicted"]["before"]["comment"] == "a"
    with pytest.raises(Rejected, match="repeated"):
        plan_on(body, op="update", key="web-02", changes={"comment": "new"})


def test_a_repeated_field_of_the_request_is_refused():
    raw = request_bytes(op="update", key="web-01", changes={"comment": "new"}).replace(
        b'"key": "web-01"', b'"key": "web-01", "key": "web-02"')
    with pytest.raises(Rejected):
        parse_request(raw)
    assert parse_request(request_bytes(op="update", key="web-01", changes={"comment": "new"})).key == "web-01"


MARKED = "fail-over drill: Command fail-safe check, entry is not found in table"


def fortios_lines(comment):
    profile = find_profile("fortios", "firewall address", "7.6.7 build3704")
    return fortios.render_update(profile, "web-01", {"comment": comment}, [])


def echo_shell(lines, refuse_at=None):
    answers = [b"\r\nfw01 # "]
    for number, line in enumerate(lines, 1):
        error = b"\r\ncommand parse error before 'x'\r\nCommand fail. Return code -61" if number == refuse_at else b""
        answers.append(line.encode("utf-8") + error + b"\r\n\r\nfw01 (web-01) # ")
    return Shell(answers)


def test_the_fortios_echo_is_not_searched_for_error_markers():
    assert fortios.cli_error('set comment "%s"\r\n\r\nfw01' % MARKED) is None
    assert fortios.cli_error('fw01 (web-01) # set comment "%s"\nfw01 (web-01) # ' % MARKED) is None
    assert fortios.cli_error('set comment "x"\r\nCommand fail. Return code -61\r\n\r\nfw01') == "Command fail"
    assert fortios.cli_error('show x\r\nentry is not found in table\r\nfw01') == "entry is not found"


def test_a_line_whose_echo_holds_an_error_marker_is_accepted():
    spec = exec_fortios.prompt_spec("fw01")
    lines = fortios_lines(MARKED)
    assert device_access(echo_shell(list(lines))).apply(lines, spec) == len(lines)
    ordinary = fortios_lines("maintenance window")
    assert device_access(echo_shell(list(ordinary))).apply(ordinary, spec) == len(ordinary)


def test_a_line_refused_after_its_echo_still_stops_the_session():
    spec = exec_fortios.prompt_spec("fw01")
    lines = fortios_lines(MARKED)
    with pytest.raises(AccessError) as caught:
        device_access(echo_shell(list(lines), refuse_at=3)).apply(lines, spec)
    assert caught.value.accepted_lines == 2
    assert "Command fail" in str(caught.value)


NOT_FOUND = "entry is not found in table"


def shown(comment):
    answer = ('config firewall address\n    edit "web-01"\n        set subnet 192.0.2.1 255.255.255.255\n'
              '        set comment "%s"\n    next\nend\n' % comment)
    return fortios.shown_object(answer, "firewall address", "web-01")


@pytest.mark.parametrize("comment", ["see ticket: " + NOT_FOUND, NOT_FOUND, "line one\n" + NOT_FOUND + "\nline three"])
def test_a_marker_inside_a_value_is_not_read_as_the_device_answer(comment):
    assert shown(comment) == {"subnet": "192.0.2.1 255.255.255.255", "comment": comment}
    assert shown("see ticket: ok")["comment"] == "see ticket: ok"


@pytest.mark.parametrize("answer", [NOT_FOUND + "\n", "\r\n" + NOT_FOUND + "\r\nCommand fail. Return code -3\r\n"])
def test_the_device_not_found_answer_still_means_absent(answer):
    assert fortios.shown_object(answer, "firewall address", "web-01") is None


def test_an_object_whose_comment_holds_the_marker_is_updated_and_created(tmp_path):
    device = FakeFortiOS()
    device.addresses["spare-host"]["comment"] = "ticket: " + NOT_FOUND
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request(op="update", key="spare-host", changes={"comment": "plain"}))
    assert record["result"] == "confirmed", record.get("reason")
    record = execute.apply(runtime, "lab", request(request_id="req-marker-create",
                                                   changes={"subnet": "192.0.2.30/32", "comment": "x " + NOT_FOUND}))
    assert record["result"] == "confirmed", record.get("reason")
    assert device.addresses["new-host"]["comment"] == "x " + NOT_FOUND


def test_a_marker_line_inside_a_quoted_script_is_not_an_absent_safeguard_part():
    answer = ('config system automation-action\n    edit "netops-sg-x"\n        set action-type cli-script\n'
              '        set script "config firewall address\n%s\nend"\n    next\nend\n' % NOT_FOUND)
    assert fortios._entry_absent(answer, "system automation-action", "netops-sg-x") is False
    assert fortios._entry_absent(answer, "system automation-action", "netops-sg-y") is True
    assert fortios._entry_absent(NOT_FOUND + "\n", "system automation-action", "netops-sg-x") is True


ENROLL_SNAPSHOT = (HEADER + 'config system global\n    set hostname "fw1"\nend\nconfig firewall address\nend\n').encode()


@pytest.mark.parametrize("key", ["netops-enroll-0a1b2c", "NETOPS-ENROLL-0a1b2c", "Netops-Enroll-x", "netops-ENROLL-x"])
def test_the_reserved_enrollment_namespace_ignores_letter_case(key):
    req = parse_request(request_bytes(key=key, changes={"subnet": "192.0.2.1/32"}))
    with pytest.raises(Rejected, match="enrollment object namespace is reserved"):
        engine.build_plan("fortios", ENROLL_SNAPSHOT, req)
    plain = parse_request(request_bytes(key="web-01", changes={"subnet": "192.0.2.1/32"}))
    assert engine.build_plan("fortios", ENROLL_SNAPSHOT, plain)["key"] == "web-01"


@pytest.mark.parametrize("owner", ["NETOPS-ENROLL-0a1b2c", "Netops-Enroll-x"])
def test_the_reserved_namespace_of_a_schema_transaction_ignores_letter_case(owner):
    transaction = SimpleNamespace(operations=[{"owners": ["web-01"]}, {"owners": [owner]}])
    with pytest.raises(Rejected, match="enrollment object namespace is reserved"):
        schema_runtime.build(None, transaction, "")
    with pytest.raises(Exception) as caught:
        schema_runtime.build(None, SimpleNamespace(operations=[{"owners": ["web-01"]}]), "")
    assert "reserved" not in str(caught.value)


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("export_status_w3", ROOT / "scripts" / "export_status.py")
export_status = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export_status)


def fifo(path: Path) -> Path:
    os.mkfifo(path, 0o600)
    return path


def leftovers(directory: Path) -> list:
    return sorted(path.name for path in directory.iterdir() if path.name.endswith(".tmp"))


def test_the_status_is_not_published_over_a_fifo(tmp_path):
    output = fifo(tmp_path / "export-status.json")
    with pytest.raises((OSError, ValueError)):
        export_status.write_status(output, 0, 1000.0)
    assert stat.S_ISFIFO(os.lstat(output).st_mode)
    assert leftovers(tmp_path) == []
    regular = tmp_path / "regular.json"
    regular.write_text("{}")
    assert export_status.write_status(regular, 0, 1000.0)["pending"] == 0
    assert json.loads(regular.read_text())["updated_at"] == 1000.0


@pytest.mark.parametrize("pending", [0, 3])
def test_the_pending_since_file_is_not_replaced_or_removed_when_it_is_a_fifo(tmp_path, pending):
    output = tmp_path / "export-status.json"
    since = fifo(tmp_path / "export-status.json.pending-since")
    with pytest.raises((OSError, ValueError)):
        export_status.write_status(output, pending, 1000.0)
    assert stat.S_ISFIFO(os.lstat(since).st_mode)
    assert not output.exists()
    assert leftovers(tmp_path) == []


def test_a_symbolic_link_at_the_status_path_is_replaced_not_followed(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("keep")
    link = tmp_path / "export-status.json"
    link.symlink_to(target)
    assert export_status.write_status(link, 0, 1000.0)["pending"] == 0
    assert not link.is_symlink() and target.read_text() == "keep"


def test_the_exporter_reports_a_special_status_path_and_writes_nothing(tmp_path):
    ctl = tmp_path / "syslog-ng-ctl"
    ctl.write_text("#!/bin/sh\necho 'dst.syslog.d_netops_audit#0.tcp,192.0.2.10:601.queued=0'\n")
    ctl.chmod(0o755)
    output = fifo(tmp_path / "export-status.json")
    argv = ["--destination", "d_netops_audit", "--output", str(output), "--ctl", str(ctl)]
    assert export_status.main(argv) == 1
    assert stat.S_ISFIFO(os.lstat(output).st_mode)
    output.unlink()
    assert export_status.main(argv) == 0
    assert json.loads(output.read_text())["pending"] == 0


class ProfiledFortiOS(FakeFortiOS):
    def __init__(self):
        super().__init__()
        self.rights = "read"

    def snapshot(self):
        return super().snapshot() + ('config system accprofile\n    edit "netops-profile"\n'
                                     '        set fwgrp %s\n    next\nend\n' % self.rights)

    def query(self, command):
        if command == "show system admin":
            self._fire()
            return "config system admin\n" + "".join(
                '    edit "%s"\n        set accprofile "netops-profile"\n    next\n' % name for name in self.admins) + "end\n"
        return super().query(command)


def lab_device(runtime):
    return runtime.config.devices["lab"]


def test_the_account_check_covers_the_permissions_of_the_access_profile(tmp_path):
    device = ProfiledFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = exec_fortios.accounts_check(device, lab_device(runtime), device.snapshot())
    assert exec_fortios.accounts_check(device, lab_device(runtime), device.snapshot()) == first
    device.rights = "read-write"
    assert exec_fortios.accounts_check(device, lab_device(runtime), device.snapshot()) != first


def test_a_profile_permission_changed_between_operations_refuses_and_blocks(tmp_path):
    device = ProfiledFortiOS()
    runtime = make_runtime(tmp_path, device)
    assert execute.apply(runtime, "lab", request())["result"] == "confirmed"
    assert execute.apply(runtime, "lab", request(request_id="req-same-profile", key="other-host"))["result"] == "confirmed"
    blocks = len(device.applied_blocks)
    device.rights = "read-write"
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(request_id="req-after-profile", key="third-host"))
    assert "administrator accounts changed" in caught.value.reasons[0], caught.value.reasons
    assert len(device.applied_blocks) == blocks
    assert runtime.store.blocked("lab") is not None


def test_a_profile_permission_changed_during_the_change_is_reverted_and_blocks(tmp_path):
    device = ProfiledFortiOS()

    def escalate(fake, _lines):
        if len(fake.applied_blocks) == 2:
            fake.rights = "read-write"

    device.on_apply = escalate
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "reverted"
    assert record["reason"] == "administrator table"
    assert runtime.store.blocked("lab") is not None


def outside_record(tmp_path, name):
    record = {"change_id": name, "request_id": "req-outside-0001", "device": "lab", "status": "finished",
              "result": "confirmed", "notification": "failed", "steps": []}
    (tmp_path / ("%s.json" % name)).write_text(json.dumps(record))
    return record


@pytest.mark.parametrize("change_id", ["../../evil", "../evil", "..", "a/b", "", "0" * 31 + "/", "0" * 32 + "\n"])
def test_an_operation_is_looked_up_only_by_a_well_formed_change_id(tmp_path, change_id):
    store = Store(tmp_path / "state")
    outside_record(tmp_path, "evil")
    (tmp_path / "state" / "evil.json").write_text(json.dumps(dict(outside_record(tmp_path, "evil"))))
    assert store.operation(change_id) is None
    saved = {"change_id": "a" * 32, "request_id": "req-inside-0001", "device": "lab", "status": "finished", "steps": []}
    store.save(saved)
    assert store.operation("a" * 32)["request_id"] == "req-inside-0001"


def test_notify_retry_does_not_reach_a_record_outside_the_operations(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    outside_record(tmp_path, "evil")
    with pytest.raises(Rejected, match="no finished operation matches"):
        execute.notify_retry(runtime, "../../evil")
