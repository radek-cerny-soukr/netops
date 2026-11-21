"""G84 Admin preview, apply, independent readback and undo on IOS XE fixtures."""
from pathlib import Path

import pytest

from fake_ios import FakeIos
from netops_admin import engine, exec_ios, execute, ios_acl, ios_save, ios_services
from netops_admin.errors import Rejected
from test_ios import make_runtime, request, steps

FIXTURES = Path(__file__).parent / "fixtures" / "ios_g84"
TARGET = "lab-ios"
SYSTEM = ios_services.SYSTEM
SERVICE_PREFIXES = ("clock timezone ", "ntp server ", "ntp source ", "logging host ", "logging trap ",
                    "logging source-interface ", "no logging trap", "ip domain name ", "ip domain-name ",
                    "ip name-server ", "ip host ")


def fixture(node, name):
    return (FIXTURES / f"d-{node}-{name}.txt").read_text()


class XEServiceTransport(FakeIos):
    def __init__(self, node):
        super().__init__(node)
        self.baseline = fixture(node, "services-base")
        self.startup_header = fixture(node, "startup-base").splitlines()[0]
        self.services = self.baseline.splitlines()[1:-1]
        self.original = list(self.services)
        self.service_position = self.lines.index(next(line for line in self.lines if line.startswith("clock timezone ")))
        self.lines = [line for line in self.lines if not line.startswith(SERVICE_PREFIXES)]
        self.sync()
        self.saved = list(self.lines)
        self.annotations = False
        self.override = {}

    def sync(self):
        self.lines = [line for line in self.lines if not line.startswith(SERVICE_PREFIXES)]
        self.lines[self.service_position:self.service_position] = self.services

    @property
    def service_rows(self):
        return fixture(self.node, "services-changed").splitlines()[1:-1]

    def query_status(self, command):
        if command in self.override:
            return 0, self.override[command]
        if command == ios_services.READ:
            return 0, "\n".join((self.baseline.splitlines()[0], *self.services, "end", ""))
        if command == ios_save.STARTUP:
            return 0, "\n".join((self.startup_header, *self.saved[2:], ""))
        return 0, self.query(command)

    def snapshot(self):
        if "show running-config" in self.override:
            return self.override["show running-config"]
        native = super().snapshot()
        if self.annotations:
            return native.removesuffix("end\n") + ios_acl.LISTING_MARK + "ipv4\n" + ios_acl.MARK + "ipv4 SAMPLE listed\nend\n"
        return native

    def _line(self, line, mode):
        if mode[0] == "config":
            additions, removals = self.transcript()
            if line in additions:
                row = additions[line]
                if row.startswith("clock timezone "):
                    self.services = [other for other in self.services if not other.startswith("clock timezone ")]
                self.services.append(row)
                self.sync()
                return ""
            if line in removals:
                self.services.remove(removals[line])
                self.sync()
                return ""
        return super()._line(line, mode)

    def transcript(self):
        additions = {row: row for row in self.service_rows + self.original}
        removals = {"no " + row: row for row in self.service_rows if row.startswith(
            ("ntp server ", "logging host ", "logging source-interface ", "ip name-server "))}
        for cli, shown in (("no ntp source", "ntp source "), ("default logging trap", "logging trap "),
                           ("no ip domain name", "ip domain"), ("no ip host netops-g84-host", "ip host ")):
            removals[cli] = next(row for row in self.service_rows if row.startswith(shown))
        return additions, removals


@pytest.mark.parametrize("node", ["iolxe", "iolxe-l2"])
@pytest.mark.parametrize("table,key,operation,changes", [
    (ios_services.NTP, "192.0.2.10", "create", {}),
    (ios_services.SYSLOG, "192.0.2.20", "create", {}),
    (ios_services.HOST, "netops-g84-host", "create", {"address": "192.0.2.40"}),
    (SYSTEM, SYSTEM, "update", {"ntp-source": "Loopback184", "logging-source": "Loopback184", "trap": "warnings",
                                "timezone": "EET 2", "domain-name": "netops-g84.invalid", "name-servers": "192.0.2.30"}),
])
def test_xe_service_apply_reads_and_restores_running_only(tmp_path, node, table, key, operation, changes):
    device = XEServiceTransport(node)
    device.lines[-1:-1] = ["interface Loopback184", "!"]
    initial = list(device.lines)
    startup = list(device.saved)
    runtime = make_runtime(tmp_path, device)
    wanted = request(device, table=table, key=key, op=operation, changes=changes)
    plan = execute.preview(runtime, TARGET, wanted)
    assert plan["result"] == "ready", plan
    assert device.sent_lines == []
    with pytest.raises(Rejected) as missing_approval:
        execute.apply(runtime, TARGET, wanted)
    assert missing_approval.value.reason_codes == ["plan_changed"]
    assert device.sent_lines == []
    result = execute.apply(runtime, TARGET, wanted, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert {"postcheck_passed", "check_identity_passed", "running_configuration_only"} <= set(steps(result))
    assert device.lines != initial and device.saved == startup and device.saves == 0
    undo = execute.preview_undo(runtime, result["change_id"], "Restore G84 baseline", issue=True)
    assert undo["result"] == "ready", undo
    restored = execute.undo(runtime, result["change_id"], "Restore G84 baseline", expected_plan_sha256=undo["plan_sha256"])
    assert restored["result"] == "confirmed", restored
    assert device.lines == initial and device.saved == startup and device.saves == 0


@pytest.mark.parametrize("node", ["iolxe", "iolxe-l2"])
@pytest.mark.parametrize("failure", ["services-denied", "truncate"])
def test_xe_service_preview_rejects_failed_readback(tmp_path, node, failure):
    device = XEServiceTransport(node)
    device.override[ios_services.READ] = (fixture(node, failure) if failure != "truncate" else
                                        device.baseline.removesuffix("end\n"))
    runtime = make_runtime(tmp_path, device)
    plan = execute.preview(runtime, TARGET, request(device, table=SYSTEM, key=SYSTEM, changes={"trap": "warnings"}))
    assert plan["result"] == "rejected" and plan["reason_codes"] == ["ios_service_read_unreadable"], plan
    assert device.sent_lines == []


@pytest.mark.parametrize("source", ["Loopback184", "Port-channel184", "Vlan184"])
def test_xe_service_source_protection_includes_logical_interfaces(source):
    measured = fixture("iolxe-l2", "running-base").replace("end\n", f"interface {source}\nend\n")
    wanted = request(FakeIos("iolxe-l2"), table=SYSTEM, key=SYSTEM, changes={"ntp-source": source})
    with pytest.raises(Rejected) as protected:
        engine.build_plan("iosxe", measured.encode(), wanted, firmware="17.18.2",
                          protected={"interface": [source.lower()]})
    assert protected.value.reason_codes == ["port_protected"]


def test_xe_existing_dns_replacement_requires_explicit_impact(tmp_path):
    device = XEServiceTransport("iolxe-l2")
    resolver = next(row for row in device.service_rows if row.startswith("ip name-server "))
    device.services.append(resolver)
    device.sync()
    runtime = make_runtime(tmp_path, device)
    args = {"table": SYSTEM, "key": SYSTEM, "changes": {"name-servers": "203.0.113.31"}}
    denied = execute.preview(runtime, TARGET, request(device, **args))
    assert denied["result"] == "rejected" and denied["reason_codes"] == ["endpoint_impact_required"]
    accepted = execute.preview(runtime, TARGET, request(device, **args, endpoint_impact=SYSTEM))
    assert accepted["result"] == "ready", accepted
    assert device.sent_lines == []


def test_xe_service_preview_refuses_numeric_timezone_name(tmp_path):
    device = XEServiceTransport("iolxe-l2")
    runtime = make_runtime(tmp_path, device)
    wanted = request(device, table=SYSTEM, key=SYSTEM, changes={"timezone": "G84 2"})
    denied = execute.preview(runtime, TARGET, wanted)
    assert denied["result"] == "rejected" and any("timezone" in reason for reason in denied["reasons"])
    assert device.sent_lines == []


@pytest.mark.parametrize("table,operation,changes,code", [
    (SYSTEM, "update", {"trap": "warnings"}, "ios_service_read_unreadable"),
    (ios_save.TABLE, "save", {}, "ios_save_diff_unreadable"),
])
@pytest.mark.parametrize("read", ["running", "timer"])
def test_xe_preflight_reports_unreadable_snapshot_or_timer(tmp_path, table, operation, changes, code, read):
    device = XEServiceTransport("iolxe-l2")
    runtime = make_runtime(tmp_path, device)
    if read == "running":
        device.override["show running-config"] = fixture(device.node, "running-base").removesuffix("end\n")
    else:
        device.query_override[exec_ios.QUERY_TIMER] = fixture(device.node, "services-denied")
    plan = execute.preview(runtime, TARGET, request(device, table=table, key=table, op=operation, changes=changes))
    assert plan["result"] == "rejected" and plan["reason_codes"] == [code], plan
    assert device.sent_lines == []


def test_xe_service_preflight_reports_refused_archive_read(tmp_path):
    device = XEServiceTransport("iolxe-l2")
    runtime = make_runtime(tmp_path, device)
    device.query_override[exec_ios.QUERY_ARCHIVE] = fixture(device.node, "services-denied")
    wanted = request(device, table=SYSTEM, key=SYSTEM, changes={"trap": "warnings"})
    plan = execute.preview(runtime, TARGET, wanted)
    assert plan["result"] == "rejected" and plan["reason_codes"] == ["ios_service_read_unreadable"], plan
    assert device.sent_lines == []


def test_xe_save_ignores_snapshot_annotations_and_verifies_native_startup(tmp_path):
    device = XEServiceTransport("iolxe-l2")
    device.annotations = True
    startup_baseline = list(device.saved)
    device.services.append(next(row for row in device.service_rows if row.startswith("ip host ")))
    device.sync()
    runtime = make_runtime(tmp_path, device)
    wanted = request(device, table=ios_save.TABLE, key=ios_save.TABLE, op="save", changes={})
    plan = execute.preview(runtime, TARGET, wanted)
    assert plan["result"] == "ready", plan
    diff = plan["predicted"]["before"]["diff"]
    assert [row for row in diff[2:] if row.startswith(("+", "-"))] == ["+" + device.services[-1]]
    with pytest.raises(Rejected) as missing_approval:
        execute.apply(runtime, TARGET, wanted)
    assert missing_approval.value.reason_codes == ["ios_save_preview_required"]
    assert device.sent_lines == []
    result = execute.apply(runtime, TARGET, wanted, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "confirmed" and "postcheck_passed" in steps(result), result
    assert device.lines == device.saved and device.sent_lines == ["write memory"]
    with pytest.raises(Rejected) as undo:
        execute.preview_undo(runtime, result["change_id"], "Save has no inverse")
    assert undo.value.reason_codes == ["undo_not_applicable"]
    device.override[ios_save.STARTUP] = fixture(device.node, "startup-base").removesuffix("end\n")
    truncated = request(device, table=ios_save.TABLE, key=ios_save.TABLE, op="save", changes={}, request_id="g84-truncated")
    refused = execute.preview(runtime, TARGET, truncated)
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["ios_save_diff_unreadable"]
    assert device.sent_lines == ["write memory"]
    del device.override[ios_save.STARTUP]
    restored_line = device.services.pop()
    device.sync()
    restore = request(device, table=ios_save.TABLE, key=ios_save.TABLE, op="save", changes={}, request_id="g84-resave")
    plan = execute.preview(runtime, TARGET, restore)
    assert plan["result"] == "ready" and "-" + restored_line in plan["predicted"]["before"]["diff"]
    returned = execute.apply(runtime, TARGET, restore, expected_plan_sha256=plan["plan_sha256"])
    assert returned["result"] == "confirmed"
    assert device.saved == device.lines == startup_baseline and device.sent_lines == ["write memory", "write memory"]


def test_xe_save_masks_bare_keys_and_keeps_a_description(tmp_path):
    device = XEServiceTransport("iolxe-l2")
    device.lines[-1:-1] = ["radius server G84-A", " key qZ", "!", "radius server G84-B", " server-key mV", "!",
                           "interface Loopback184", " description server-key rotation status", "!"]
    runtime = make_runtime(tmp_path, device)
    wanted = request(device, table=ios_save.TABLE, key=ios_save.TABLE, op="save", changes={})
    plan = execute.preview(runtime, TARGET, wanted)
    assert plan["result"] == "ready", plan
    diff = plan["predicted"]["before"]["diff"]
    assert diff.count("+ [redacted]") == 2
    assert "+ description server-key rotation status" in diff
    assert not any("qZ" in row or "mV" in row for row in diff)
    assert device.sent_lines == []


@pytest.mark.parametrize("protocol", ["radius", "tacacs+"])
def test_xe_save_masks_aaa_server_private_key_in_diff_and_context(tmp_path, protocol):
    device = XEServiceTransport("iolxe-l2")
    header = f"aaa group server {protocol} G84"
    context = " server-private 192.0.2.54 key 7 REVIEW675_CONTEXT"
    removed = " server-private 192.0.2.55 key REVIEW675_OLD"
    added = " server-private 192.0.2.55 key 0 REVIEW675_NEW"
    device.lines[-1:-1] = [header, context, added, "!"]
    device.saved[-1:-1] = [header, context, removed, "!"]
    runtime = make_runtime(tmp_path, device)
    wanted = request(device, table=ios_save.TABLE, key=ios_save.TABLE, op="save", changes={})
    plan = execute.preview(runtime, TARGET, wanted)
    assert plan["result"] == "ready", plan
    diff = plan["predicted"]["before"]["diff"]
    assert any(header in row for row in diff)
    assert all(leader + " [redacted]" in diff for leader in (" ", "-", "+"))
    assert all("REVIEW675_" not in row for row in diff)
    assert not device.sent_lines
