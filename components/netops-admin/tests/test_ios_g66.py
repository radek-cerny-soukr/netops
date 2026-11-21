"""G66 public Admin operations over measured IOS configurations and fake transport."""
from pathlib import Path
import re

import pytest

from fake_ios import FakeIos
from netops_admin import engine, exec_ios, execute, ios, ios_save, ios_services
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_ios import make_runtime, request, steps

F = Path(__file__).parent / "fixtures" / "ios_g66"
TARGET = "lab-ios"
TABLE = ios_services.SYSTEM


def fixture(name):
    return (F / (name + ".txt")).read_text()


MEASURED = fixture("d-iosv-changed")
NTP = re.search(r"(?m)^ntp server (\S+)$", MEASURED)[1]
SYSLOG = re.search(r"(?m)^logging host (\S+)$", MEASURED)[1]
STATIC_HOST, HOST_IP = re.search(r"(?m)^ip host (\S+) (\S+)$", MEASURED).groups()
DNS = re.search(r"(?m)^ip name-server (\S+)$", MEASURED)[1]
SETTINGS = {"ntp-source": "Loopback166", "logging-source": "Loopback166", "trap": "warnings", "name-servers": DNS}


class ServiceIos(FakeIos):
    def __init__(self, node="iosv"):
        super().__init__(node)
        data = fixture("d-iosv-base" if node == "iosv" else "d-iolxe-base")
        for line in data.splitlines():
            if line.startswith(("ip domain name ", "clock timezone ")):
                family = "ip domain name" if line.startswith("ip domain") else "clock timezone"
                self.lines = [row for row in self.lines if not row.startswith(family + " ")]
                self.lines.insert(self.lines.index("end"), line)
        self.lines[-1:-1] = ["interface Loopback166", "!"]
        self.saved = list(self.lines)
        self.fail_read = None

    def _line(self, line, mode):
        if mode[0] != "config":
            return super()._line(line, mode)
        families = (f"ntp server {NTP}", f"logging host {SYSLOG}", "ntp source", "logging source-interface",
                    "logging trap", "ip domain name", "clock timezone", "ip name-server", f"ip host {STATIC_HOST}")
        body = line.removeprefix("no ").removeprefix("default ")
        for family in families:
            if body != family and not body.startswith(family + " "):
                continue
            if line == "no logging source-interface":
                return "% Incomplete command."
            self.lines = [row for row in self.lines if row != family and not row.startswith(family + " ")]
            if not line.startswith(("no ", "default ")):
                self.lines.insert(self.lines.index("end"), line)
            elif line == "no logging trap":
                self.lines.insert(self.lines.index("end"), line)
            return ""
        return super()._line(line, mode)

    def query_status(self, command):
        if self.fail_read and command == self.fail_read[0]:
            answer = self.fail_read[1]
            if isinstance(answer, Exception):
                raise answer
            return 0, answer
        if command == ios_services.READ:
            prefix = ("hostname ", "ntp ", "logging ", "no logging trap", "ip host ", "ip name-server ",
                      "ip domain name ", "clock timezone ")
            return 0, "\n".join(line for line in self.lines if line == "end" or line.startswith(prefix))
        if command == ios_save.STARTUP:
            header = fixture("d-iosv-startup-base").splitlines()[0]
            return 0, header + "\n" + "\n".join(self.saved[2:]) + "\n"
        return 0, self.query(command)


@pytest.mark.parametrize("table,key,changes,op,command", [
    (ios_services.NTP, NTP, {}, "create", f"ntp server {NTP}"),
    (ios_services.SYSLOG, SYSLOG, {}, "create", f"logging host {SYSLOG}"),
    (ios_services.HOST, STATIC_HOST, {"address": HOST_IP}, "create", f"ip host {STATIC_HOST} {HOST_IP}"),
    (TABLE, TABLE, SETTINGS, "update", "logging source-interface Loopback166"),
    (TABLE, TABLE, {"timezone": "G66 1", "domain-name": "lab.example"}, "update", "clock timezone G66 1 0"),
])
def test_preview_apply_readback_undo(tmp_path, table, key, changes, op, command):
    device = ServiceIos()
    runtime = make_runtime(tmp_path, device)
    original = list(device.lines)
    wanted = request(device, table=table, key=key, changes=changes, op=op)
    plan = execute.preview(runtime, TARGET, wanted)
    assert plan["result"] == "ready", plan
    assert not device.sent_lines and command in plan["commands"]
    with pytest.raises(Rejected, match="approved preview"):
        execute.apply(runtime, TARGET, wanted)
    record = execute.apply(runtime, TARGET, wanted, expected_plan_sha256=plan["plan_sha256"])
    assert record["result"] == "confirmed", (record["reason"], steps(record), record.get("postcheck_differences"))
    assert {"postcheck_passed", "check_identity_passed", "configuration_saved"} <= set(steps(record))
    assert command in device.lines
    undo = execute.preview_undo(runtime, record["change_id"], "G66 test", issue=True)
    assert undo["result"] == "ready", undo
    restored = execute.undo(runtime, record["change_id"], "G66 test", expected_plan_sha256=undo["plan_sha256"])
    assert restored["result"] == "confirmed", restored
    assert sorted(device.lines) == sorted(original)
    assert device.lines == device.saved


@pytest.mark.parametrize("answer,reason", [
    ("", "ios_service_read_unreadable"),
    (fixture("d-iosv-denied"), "ios_service_read_unreadable"),
    ("hostname lab\n --More--", "ios_service_read_unreadable"),
    (AccessError("operation timed out"), "ios_service_read_timeout"),
])
def test_service_read_fails_closed(tmp_path, answer, reason):
    device = ServiceIos()
    runtime = make_runtime(tmp_path, device)
    device.fail_read = ios_services.READ, answer
    wanted = request(device, table=TABLE, key=TABLE, changes={"trap": "warnings"})
    preview = execute.preview(runtime, TARGET, wanted)
    assert reason in preview["reason_codes"], preview
    assert not device.sent_lines


def test_existing_options_and_protected_sources(tmp_path):
    device = ServiceIos()
    runtime = make_runtime(tmp_path, device)
    device.lines.insert(-1, f"ntp server {NTP} prefer")
    device.saved = list(device.lines)
    req = request(device, table=ios_services.NTP, key=NTP, changes={}, op="delete")
    assert execute.preview(runtime, TARGET, req)["result"] != "ready"
    req = request(device, table=TABLE, key=TABLE, changes={"ntp-source": "Loopback166"})
    with pytest.raises(Rejected) as caught:
        engine.build_plan(device.platform, device.snapshot().encode(), req, firmware=device.firmware,
                          protected={"interface": ["Loopback166"]})
    assert caught.value.reason_codes == ["port_protected"]
    assert not device.sent_lines


def test_iosxe_read_as_measured_and_untested_version_is_warning():
    text = fixture("d-iolxe-base")
    device = ServiceIos("iolxe")
    state = ios.load(text, "17.18.2").entries(TABLE)[TABLE].attributes
    assert state["timezone"] == "CET 1 0"
    wanted = request(device, table=TABLE, key=TABLE, changes={"timezone": "EET 2 00"})
    plan = engine.build_plan("iosxe", text.encode(), wanted, firmware="17.18.3")
    assert plan["firmware_support"]["status"] != "tested"
    assert "clock timezone EET 2 0" in plan["commands"]
    assert plan["inverse"] == ["configure terminal", "clock timezone CET 1 0", "end"]


def save_request(device):
    return request(device, table=ios_save.TABLE, key=ios_save.TABLE, op="save", changes={})


def test_save_diff_visible_redacted_and_verified(tmp_path):
    device = ServiceIos()
    runtime = make_runtime(tmp_path, device)
    device.lines[-1:-1] = [f"logging host {SYSLOG}", " description foreign diagnostic link",
                           "snmp-server community ab RO"]
    wanted = save_request(device)
    preview = execute.preview(runtime, TARGET, wanted)
    assert preview["result"] == "ready", preview
    diff = preview["predicted"]["before"]["diff"]
    assert f"+logging host {SYSLOG}" in diff
    assert "+ description foreign diagnostic link" in diff
    assert "+[redacted]" in diff and not any("community ab" in line for line in diff)
    assert not device.sent_lines
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, TARGET, wanted)
    assert caught.value.reason_codes == ["ios_save_preview_required"]
    record = execute.apply(runtime, TARGET, wanted, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed" and record["reason"] is None, record
    assert device.lines == device.saved and device.sent_lines == ["write memory"]
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, record["change_id"], "save is irreversible")
    assert caught.value.reason_codes == ["undo_not_applicable"]


def test_save_refuses_changed_or_incomplete_startup(tmp_path):
    device = ServiceIos()
    runtime = make_runtime(tmp_path, device)
    wanted = save_request(device)
    preview = execute.preview(runtime, TARGET, wanted)
    assert preview["result"] == "ready", preview
    device.saved.insert(-1, "ntp authentication-key 1 md5 cd")
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, TARGET, wanted, expected_plan_sha256=preview["plan_sha256"])
    assert caught.value.reason_codes == ["plan_changed"]
    device.fail_read = ios_save.STARTUP, fixture("d-iosv-startup-base").rsplit("end", 1)[0]
    refused = execute.preview(runtime, TARGET, wanted)
    assert "ios_save_diff_unreadable" in refused["reason_codes"], refused
    assert not device.sent_lines


def test_save_unreadable_timer_and_failed_readback(tmp_path):
    device = ServiceIos()
    runtime = make_runtime(tmp_path, device)
    wanted = save_request(device)
    device.query_override[exec_ios.QUERY_TIMER] = device._timer_text().replace(
        "%No Rollback Confirmed Change pending", "unreadable")
    not_ready = execute.preview(runtime, TARGET, wanted)
    assert not_ready["result"] == "rejected"
    assert not device.sent_lines
    del device.query_override[exec_ios.QUERY_TIMER]
    plan = execute.preview(runtime, TARGET, wanted)
    assert plan["result"] == "ready", plan

    def truncate_after_send(dev, commands):
        if ios_save.COMMAND in commands:
            dev.fail_read = ios_save.STARTUP, fixture("d-iosv-startup-base").rsplit("end", 1)[0]

    device.on_apply = truncate_after_send
    result = execute.apply(runtime, TARGET, wanted, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "unknown"
    assert "postcheck_passed" not in steps(result)
    assert device.sent_lines == ["write memory"]


@pytest.mark.parametrize("timer_read,code", [
    ("pending", "rollback_timer_pending"),
    ("disconnected", "ios_save_diff_unreadable"),
])
def test_save_rechecks_timer_after_admission(tmp_path, timer_read, code):
    class SaveWire(ServiceIos):
        def query(self, command):
            if command == exec_ios.QUERY_TIMER and runtime.store.running(TARGET):
                if timer_read == "disconnected":
                    raise AccessError("synthetic private IOS diagnostic")
                self.foreign_timer = {"configured": self.now, "minutes": 10, "user": "other-operator"}
            return super().query(command)

    device = SaveWire()
    runtime = make_runtime(tmp_path, device)
    wanted = save_request(device)
    plan = execute.preview(runtime, TARGET, wanted)
    assert plan["result"] == "ready"
    saved = list(device.saved)

    record = execute.apply(runtime, TARGET, wanted, expected_plan_sha256=plan["plan_sha256"])

    assert (record["result"], record["reason_codes"]) == ("rejected", [code])
    assert "change_start" not in steps(record)
    assert not device.sent_lines and device.saved == saved
    assert device.foreign_touched == []
    assert runtime.store.blocked(TARGET) is None
    assert "synthetic private IOS diagnostic" not in repr(runtime.store.records())


def test_save_multiline_and_short_credentials_are_masked():
    old = fixture("d-iosv-base")
    new = old.replace("end\n", "banner motd ^C\nliteral-banner-data\n^C\n"
                      "crypto pki certificate chain TEST\n certificate self-signed 01\n  1234abcd\n  quit\n"
                      "radius-server host 192.0.2.100 key xy\nntp authentication-key 1 md5 x\n"
                      "service password-encryption\nend\n")
    fw = "15.9(3)M12"
    diff = "\n".join(ios_save._diff(ios_save._lines(old, fw), ios_save._lines(new, fw)))
    assert all(value not in diff for value in ("literal-banner-data", "1234abcd", "key xy", "md5 x"))
    assert "+service password-encryption" in diff


@pytest.mark.parametrize("field", ["server-key", "key"])
@pytest.mark.parametrize("context", [False, True])
def test_review_8_save_masks_radius_coa_changes_and_context(tmp_path, field, context):
    device = ServiceIos()
    prefix = ["aaa server radius dynamic-author", " client 192.0.2.100"]
    old = f"  {field} 7 fake-radius-old"
    new = old if context else f"  {field} 7 fake-radius-new"
    device.saved[-1:-1] = [*prefix, old, " auth-type any"]
    device.lines[-1:-1] = [*prefix, new, " auth-type all" if context else " auth-type any"]
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, TARGET, save_request(device))
    assert preview["result"] == "ready"
    diff = preview["predicted"]["before"]["diff"]
    assert ("   [redacted]" if context else "+  [redacted]") in diff
    assert not any("fake-radius-" in line for line in diff)


@pytest.mark.parametrize("table,key,line,op,changes", [
    (ios_services.NTP, NTP, f"ntp server {NTP}", "delete", {}),
    (ios_services.SYSLOG, SYSLOG, f"logging host {SYSLOG}", "delete", {}),
    (TABLE, TABLE, f"ip name-server {DNS}", "update", {"name-servers": None}),
])
def test_review_11_removing_last_service_target_requires_impact(tmp_path, table, key, line, op, changes):
    device = ServiceIos()
    device.lines.insert(-1, line)
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    fields = dict(table=table, key=key, changes=changes, op=op)
    refused = execute.preview(runtime, TARGET, request(device, **fields))
    assert refused["reason_codes"] == ["endpoint_impact_required"]
    assert not device.sent_lines
    acknowledged = request(device, **fields, endpoint_impact=key)
    preview = execute.preview(runtime, TARGET, acknowledged)
    assert preview["result"] == "ready" and "Explicit service impact accepted for " + key in preview["prechecks"]
    record = execute.apply(runtime, TARGET, acknowledged, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed" and line not in device.lines
    assert execute.undo(runtime, record["change_id"], "G66 return")["result"] == "confirmed"
    assert line in device.lines


def test_review_g66_service_readback_uses_filtered_admin_query(tmp_path):
    device = ServiceIos()
    device.check_override = {
        "show logging": fixture("d-iosv-denied"),
        "show hosts": "Default domain is lab.example\n",
        ios_services.READ: fixture("d-iosv-denied"),
    }
    runtime = make_runtime(tmp_path, device)
    change = request(device, table=TABLE, key=TABLE, changes={"name-servers": DNS})
    preview = execute.preview(runtime, TARGET, change)
    assert preview["result"] == "ready"
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed" and "check_identity_passed" in steps(result)
    assert execute.undo(runtime, result["change_id"], "G66 filtered readback return")["result"] == "confirmed"
    assert not set(device.check_override).intersection(device.check_queries)
