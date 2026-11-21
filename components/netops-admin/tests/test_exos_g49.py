from pathlib import Path

import pytest

from fake_exos import FakeExos
from netops_admin import engine, execute, mcp_server
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_execute_exos import make_runtime, request, steps

FIXTURES = Path(__file__).parent / "fixtures" / "exos_g49"
DIFF = "show configuration difference primary"
SCENARIOS = {
    "ntp-server": ("VR-Mgmt/192.0.2.24", "show ntp server", "ntp",
                   "configure ntp server add 192.0.2.24 vr VR-Mgmt",
                   "configure ntp server delete 192.0.2.24", {}),
    "syslog-target": ("VR-Mgmt/192.0.2.25/514/local1", "show log configuration target syslog", "ems",
                      "configure syslog add 192.0.2.25 udp-port 514 vr VR-Mgmt local1",
                      "configure syslog delete 192.0.2.25 udp-port 514 vr VR-Mgmt local1", {"severity": "warning"}),
    "dns-server": ("VR-Default/192.0.2.26", "show dns-client", "netTools",
                   "configure dns-client add name-server 192.0.2.26 vr VR-Default",
                   "configure dns-client delete name-server 192.0.2.26 vr VR-Default", {}),
}
SEVERITY = "configure log target syslog 192.0.2.25 udp-port 514 vr VR-Mgmt local1 severity warning"
SEVERITY_RESET = SEVERITY.removesuffix("warning") + "debug-data"


def fixture(device, command, phase="before"):
    name = command.removeprefix("show ").replace(" ", "-").lower()
    return (FIXTURES / f"{device}-{name}__{phase}.txt").read_text()


class ServiceExos(FakeExos):
    def __init__(self, device, table):
        super().__init__()
        self.device, self.table = device, table
        self.key, self.read, self.module, self.add, self.remove, _attrs = SCENARIOS[table]
        output = fixture(device, "show running-services", "active")
        prefix = {"ntp-server": "configure ntp", "syslog-target": ("configure syslog", "configure log", "disable log"),
                  "dns-server": "configure dns-client"}[table]
        self.owned = [line for line in output.splitlines() if line.startswith(prefix)]
        self.present = False
        self.severity = False
        self.checks = []
        self.bad_answer = None
        self.diff = ""
        self.check_diff = None

    def snapshot(self):
        text = super().snapshot()
        text = text.replace("configure syslog add 192.0.2.10:514 vr VR-Default local0\n", "")
        text += "# Module ntp configuration.\n"
        if self.present:
            heading = "# Module %s configuration.\n" % self.module
            lines = self.owned
            if self.table == "syslog-target" and not self.severity:
                lines = [line.replace("severity Warning", "severity Debug-Data") for line in self.owned]
            text = text.replace(heading, heading + "\n".join(lines) + "\n")
        return text

    def _command(self, words, automatic):
        command = " ".join(words)
        if command == self.add:
            assert not self.present
            self.present = True
        elif command == self.remove:
            assert self.present
            self.present = False
            self.severity = False
        elif command in (SEVERITY, SEVERITY_RESET):
            assert self.present
            self.severity = command == SEVERITY
        else:
            return super()._command(words, automatic)
        self.unsaved = True
        return True

    def apply(self, steps_, spec):
        result = super().apply(steps_, spec)
        if steps_[0] == ("ask", "save configuration", b"(y/N)"):
            self.diff = ""
        return result

    def answer(self, command):
        if command == DIFF:
            return self.diff
        answer = super().answer(command)
        if command == "show switch":
            answer += "Config Selected:  primary.cfg\n"
        return answer

    def check_query_status(self, command):
        self.checks.append(command)
        if command == DIFF and self.check_diff is not None:
            return self.check_diff
        if command in ("show switch", DIFF):
            return 0, self.answer(command)
        assert command == self.read
        if isinstance(self.bad_answer, Exception):
            raise self.bad_answer
        if self.bad_answer is not None:
            return self.bad_answer
        phase = "active" if self.severity else "created" if self.present else "before"
        return 0, fixture(self.device, command, phase)


@pytest.mark.parametrize("device,firmware", [("d-exos", "33.6.1.14"), ("x440", "33.7.1.6")])
@pytest.mark.parametrize("table", SCENARIOS)
def test_confirmed_service_and_exact_undo(tmp_path, device, firmware, table):
    transport = ServiceExos(device, table)
    transport.firmware = firmware
    runtime = make_runtime(tmp_path, transport, firmware=firmware)
    key, read, _module, add, remove, attributes = SCENARIOS[table]
    change = request(table=table, key=key, op="create", changes=attributes)
    baseline = transport.snapshot()
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready", preview
    expected = [add, SEVERITY] if attributes else [add]
    assert preview["commands"] == expected
    assert not transport.applied_blocks and transport.snapshot() == baseline
    with pytest.raises(Rejected, match="approved preview"):
        execute.apply(runtime, "sw", change)
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert "check_identity_passed" in steps(record)
    assert "running_configuration_only" in steps(record)
    assert transport.present and transport.saves == 0
    risky = execute.preview(runtime, "sw", request(table=table, key=key, op="delete", changes={},
                                                   request_id="unapproved-delete"))
    assert risky["reason_codes"] == ["exos_service_impact_required"]
    undo = execute.preview_undo(runtime, record["change_id"], "restore original configuration", issue=True)
    assert undo["result"] == "ready", undo
    assert undo["commands"] == [remove]
    returned = execute.undo(runtime, record["change_id"], "restore original configuration",
                            expected_plan_sha256=undo["plan_sha256"])
    assert returned["result"] == "confirmed", returned
    assert transport.snapshot() == baseline and transport.saves == 0 and not transport.timers
    assert transport.checks == [read] * 6


def test_x440_dns_undo_with_approved_impact_and_active_save_preview(tmp_path, monkeypatch):
    transport = ServiceExos("x440", "dns-server")
    transport.firmware = "33.7.1.6"
    runtime = make_runtime(tmp_path, transport, firmware=transport.firmware)
    key, read, _module, add, remove, attrs = SCENARIOS["dns-server"]
    change = request(table="dns-server", key=key, op="create", changes=attrs, endpoint_impact=key)
    baseline = transport.snapshot()
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready" and preview["commands"] == [add]
    applied = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed" and "check_identity_passed" in steps(applied)

    transport.diff = (
        "+++ Running Configuration Thu Nov 19 18:55:39 2026\n"
        f"+{add}\n"
    )
    transport.check_diff = (0, transport.diff.replace("18:55:39", "18:55:47"))
    save = request(table="startup-config", op="save", key="startup-config", changes={}, request_id="x440-active-save")
    save_preview = execute.preview(runtime, "sw", save)
    assert save_preview["result"] == "ready"
    assert save_preview["predicted"]["before"]["diff"] == ["+ " + add]

    original_read = transport.check_query_status

    def check_query_status(command):
        if command == read and not transport.present:
            return 0, fixture("x440", read, "removed")
        return original_read(command)

    monkeypatch.setattr(transport, "check_query_status", check_query_status)
    reason = "restore original DNS configuration"
    undo = execute.preview_undo(runtime, applied["change_id"], reason, issue=True)
    assert undo["result"] == "ready" and undo["commands"] == [remove]
    returned = execute.undo(runtime, applied["change_id"], reason, expected_plan_sha256=undo["plan_sha256"])
    assert returned["result"] == "confirmed" and "check_identity_passed" in steps(returned)
    assert returned["plan"]["endpoint_impact"] == key
    assert transport.snapshot() == baseline and transport.saves == 0 and not transport.timers


@pytest.mark.parametrize("table", SCENARIOS)
def test_refused_or_truncated_operational_read(tmp_path, table):
    transport = ServiceExos("d-exos", table)
    runtime = make_runtime(tmp_path, transport)
    key, read, _module, _add, _delete, attrs = SCENARIOS[table]
    change = request(table=table, key=key, op="create", changes=attrs)
    raw = fixture("d-exos", read, "created")
    for answer, code in (
        ((254, "This user does not have permissions for this command."), "exos_service_readback_unreadable"),
        ((0, "\n".join(raw.splitlines()[:-1])), "exos_service_readback_unreadable"),
        (AccessError("query timed out"), "exos_service_read_timeout"),
    ):
        transport.bad_answer = answer
        preview = execute.preview(runtime, "sw", change)
        assert preview["result"] == "rejected" and preview["reason_codes"] == [code]
    assert not transport.applied_blocks


def test_measured_sntp_and_ntp_status_are_distinct():
    from netops_admin import exos_services

    class Cli:
        def check_query_status(self, command):
            return 0, fixture("d-exos", command)

    sntp = exos_services.observe(Cli(), "sntp-server", "primary")
    assert sntp["server"] and sntp["vr"] == "VR-Mgmt"
    assert exos_services.observe(Cli(), "sntp-server", "secondary") is None
    assert exos_services.observe(Cli(), "ntp", "VR-Mgmt") == {"admin-state": "disabled"}


@pytest.mark.parametrize("dirty", [False, True])
def test_save_is_separate_confirmed_and_never_undoable(tmp_path, dirty):
    transport = ServiceExos("d-exos", "ntp-server")
    transport.unsaved = dirty
    if dirty:
        transport.diff = fixture("d-exos", "show difference-ro", "active")
        transport.diff += '+configure snmp add community "fixture-secret" readonly\n'
    runtime = make_runtime(tmp_path, transport)
    change = request(table="startup-config", key="startup-config", op="save", changes={})
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready", preview
    assert preview["return_mechanism"] == "irreversible"
    assert preview["predicted"]["before"]["unsaved_changes"] is dirty
    assert "fixture-secret" not in repr(preview)
    assert transport.saves == 0 and not transport.applied_blocks
    with pytest.raises(Rejected, match="approved preview"):
        execute.apply(runtime, "sw", change)
    original = transport.snapshot()
    result = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert mcp_server.summary(result)["return_mechanism"] == "irreversible"
    assert engine._read_plan(result["plan"]) == result["plan"]
    assert transport.saves == 1 and original == transport.snapshot()
    assert not transport.unsaved and not transport.timers
    assert execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])["change_id"] == result["change_id"]
    with pytest.raises(Rejected, match="irreversible"):
        execute.preview_undo(runtime, result["change_id"], "save is not reversible")


def test_save_hash_binds_redacted_changes_and_ro_permission(tmp_path):
    transport = ServiceExos("x440", "dns-server")
    runtime = make_runtime(tmp_path, transport)
    change = request(table="startup-config", key="startup-config", op="save", changes={})
    raw = fixture("x440", "show difference-ro", "active")
    transport.diff = raw + '+configure snmp add community "fixture-secret" readonly\n'
    ready = execute.preview(runtime, "sw", change)
    assert ready["result"] == "ready"
    transport.diff = transport.diff.replace("fixture-secret", "replacement")
    stale = execute.preview(runtime, "sw", change)
    assert ready["predicted"] == stale["predicted"]
    assert ready["plan_sha256"] != stale["plan_sha256"]
    with pytest.raises(Rejected) as mismatch:
        execute.apply(runtime, "sw", change, expected_plan_sha256=ready["plan_sha256"])
    assert mismatch.value.reason_codes == ["plan_changed"]
    transport.check_diff = 254, "This user does not have permissions for this command."
    denied = execute.preview(runtime, "sw", change)
    assert denied["result"] == "rejected"
    assert denied["reason_codes"] == ["exos_save_check_denied"]
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, "sw", change, expected_plan_sha256=stale["plan_sha256"])
    assert refused.value.reason_codes == ["exos_save_check_denied"]
    assert transport.saves == 0 and not transport.applied_blocks


@pytest.mark.parametrize("device", ["d-exos", "x440"])
def test_save_preview_preserves_live_service_and_vlan_changes(tmp_path, device):
    transport = ServiceExos(device, "ntp-server")
    transport.diff = fixture(device, "show difference-ro", "active")
    transport.diff += (
        '-configure vlan netops-g48 add ports 10 tagged\n'
        '+configure ntp server add 192.0.2.27 key 3 vr VR-Default\n'
        '+configure vlan netops-g48 description "encrypted uplink"\n'
    )
    runtime = make_runtime(tmp_path, transport)
    change = request(table="startup-config", key="startup-config", op="save", changes={})
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready"
    assert preview["predicted"]["before"]["diff"] == [
        f"{line[0]} {line[1:]}" for line in transport.diff.splitlines()
    ]


@pytest.mark.parametrize("line,kind", [
    ('configure snmp add community "fixture-secret" readonly', "snmp community"),
    ('configure snmpv3 add user test authentication sha "fixture-secret"', "snmpv3 key"),
    ('configure account operator encrypted "fixture-secret"', "password"),
    ('create account user operator "fixture-secret"', "password"),
    ('configure radius mgmt-access primary shared-secret "fixture-secret"', "radius secret"),
    ('configure tacacs primary shared-secret "fixture-secret"', "tacacs secret"),
    ('create ntp key 3 sha256 encrypted "fixture-secret"', "key"),
    ('create macsec connectivity-association test pre-shared-key ckn name cak "fixture-secret"', "key"),
])
def test_save_preview_labels_sensitive_changes(tmp_path, line, kind):
    transport = ServiceExos("d-exos", "ntp-server")
    transport.diff = f"-{line}\n"
    runtime = make_runtime(tmp_path, transport)
    change = request(table="startup-config", key="startup-config", op="save", changes={})
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready"
    assert "fixture-secret" not in repr(preview)
    assert preview["predicted"]["before"]["diff"] == [f"- [redacted: {kind}]"]


def test_save_ignores_only_the_live_timestamp_header(tmp_path):
    transport = ServiceExos("d-exos", "ntp-server")
    contents = fixture("d-exos", "show difference-ro", "active")
    transport.unsaved = True
    transport.diff = "+++ Running Configuration Thu Nov 19 15:13:11 2026\n" + contents
    transport.check_diff = (0, transport.diff.replace("15:13:11", "15:13:12"))
    runtime = make_runtime(tmp_path, transport)
    change = request(table="startup-config", key="startup-config", op="save", changes={})
    first = execute.preview(runtime, "sw", change)
    assert first["result"] == "ready", first
    transport.diff = transport.diff.replace("15:13:11", "15:13:13")
    second = execute.preview(runtime, "sw", change)
    assert first["plan_sha256"] == second["plan_sha256"]
    assert first["predicted"]["before"]["changed_lines"] == len(contents.splitlines())
    transport.check_diff = (0, transport.diff.replace("local1", "local2"))
    assert execute.preview(runtime, "sw", change)["reason_codes"] == ["exos_save_check_denied"]


def test_service_on_untested_firmware_still_previews(tmp_path):
    transport = ServiceExos("d-exos", "ntp-server")
    transport.firmware = "31.7.3.37"
    runtime = make_runtime(tmp_path, transport, firmware=transport.firmware)
    change = request(table="ntp-server", key=SCENARIOS["ntp-server"][0], op="create", changes={})
    result = execute.preview(runtime, "sw", change)
    assert result["result"] == "ready" and result["firmware_support"]["status"] == "untested"
    assert not transport.applied_blocks


def test_syslog_severity_undo_keeps_the_existing_target(tmp_path):
    transport = ServiceExos("x440", "syslog-target")
    transport.present = True
    runtime = make_runtime(tmp_path, transport)
    baseline = transport.snapshot()
    key = SCENARIOS["syslog-target"][0]
    change = request(table="syslog-target", key=key, op="update", changes={"severity": "warning"})
    preview = execute.preview(runtime, "sw", change)
    assert preview["commands"] == [SEVERITY]
    applied = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed"
    undo = execute.preview_undo(runtime, applied["change_id"], "restore the existing target", issue=True)
    assert undo["commands"] == [SEVERITY_RESET]
    returned = execute.undo(runtime, applied["change_id"], "restore the existing target", undo["plan_sha256"])
    assert returned["result"] == "confirmed" and transport.present and transport.snapshot() == baseline


class SntpExos(ServiceExos):
    def __init__(self):
        super().__init__("d-exos", "ntp-server")
        self.read = "show sntp-client"
        self.original = fixture(self.device, self.read)
        self.primary_line = next(line for line in self.original.splitlines() if line.startswith("Primary server:"))
        self.server = tuple(self.primary_line.partition(":")[2].split())
        self.current = self.server

    def snapshot(self):
        base = super().snapshot()
        return base.replace("192.0.2.123 vr VR-Default", "%s vr %s" % self.current)

    def _command(self, words, automatic):
        if words[:3] == ["configure", "sntp-client", "primary"] and words[4] == "vr":
            self.current = words[3], words[5]
            self.unsaved = True
            return True
        return super()._command(words, automatic)

    def check_query_status(self, command):
        assert command == self.read
        # Derived from the real response by replacing only the primary server and VR fields.
        return 0, self.original.replace(self.primary_line, "Primary server:%s  %s" % self.current)


def test_sntp_restores_the_existing_server_and_vr(tmp_path):
    transport = SntpExos()
    runtime = make_runtime(tmp_path, transport)
    baseline = transport.snapshot()
    changes = {"server": "192.0.2.34", "vr": "VR-Default"}
    change = request(table="sntp-server", key="primary", op="update", changes=changes, endpoint_impact="primary")
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready", preview
    applied = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed" and transport.current == ("192.0.2.34", "VR-Default")
    undo = execute.preview_undo(runtime, applied["change_id"], "restore original SNTP", issue=True)
    returned = execute.undo(runtime, applied["change_id"], "restore original SNTP", undo["plan_sha256"])
    assert returned["result"] == "confirmed" and transport.snapshot() == baseline


def test_save_with_a_lost_readback_is_not_repeated(tmp_path):
    transport = ServiceExos("d-exos", "ntp-server")
    runtime = make_runtime(tmp_path, transport)
    change = request(table="startup-config", key="startup-config", op="save", changes={})
    preview = execute.preview(runtime, "sw", change)

    def lose_readback(device, _steps):
        device.check_diff = 254, "This user does not have permissions for this command."

    transport.on_apply = lose_readback
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "unknown"
    assert "postcheck_failed" in steps(record) and "postcheck_passed" not in steps(record)
    assert execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])["change_id"] == record["change_id"]
    assert transport.saves == 1


@pytest.mark.parametrize("fault,code", [
    ("denied", "exos_save_check_denied"),
    ("disconnected", "exos_save_diff_unreadable"),
])
def test_save_rechecks_independent_diff_after_admission(tmp_path, fault, code):
    class SaveWire(ServiceExos):
        def check_query_status(self, command):
            if command == DIFF and runtime.store.running("sw"):
                if fault == "disconnected":
                    raise OSError("synthetic private EXOS diagnostic")
                return 254, "This user does not have permissions for this command."
            return super().check_query_status(command)

    wire = SaveWire("d-exos", "ntp-server")
    wire.unsaved = True
    wire.diff = fixture("d-exos", "show difference-ro", "active")
    runtime = make_runtime(tmp_path, wire)
    change = request(table="startup-config", key="startup-config", op="save", changes={})
    plan = execute.preview(runtime, "sw", change)
    assert plan["result"] == "ready"

    record = execute.apply(runtime, "sw", change, expected_plan_sha256=plan["plan_sha256"])

    assert (record["result"], record["reason_codes"]) == ("rejected", [code])
    assert "change_start" not in steps(record)
    assert wire.unsaved and wire.saves == 0 and not wire.applied_blocks and not wire.timers
    assert runtime.store.blocked("sw") is None
    assert "synthetic private EXOS diagnostic" not in repr(runtime.store.records())


def test_save_with_a_lost_confirmation_is_blocked_and_never_repeated(tmp_path):
    wire = ServiceExos("d-exos", "ntp-server")
    runtime = make_runtime(tmp_path, wire)
    change = request(table="startup-config", key="startup-config", op="save", changes={})
    plan = execute.preview(runtime, "sw", change)
    assert plan["result"] == "ready"

    def lose_confirmation(_wire, commands):
        assert commands == [("ask", "save configuration", b"(y/N)"), "y"]
        raise AccessError("synthetic private EXOS diagnostic")

    wire.on_apply = lose_confirmation
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=plan["plan_sha256"])

    assert (record["result"], record["reason"]) == ("unknown", "ExtremeXOS save acceptance or readback is unverified")
    assert "postcheck_failed" in steps(record) and "change_applied" not in steps(record)
    assert runtime.store.blocked("sw")["change_id"] == record["change_id"]
    assert execute.recover(runtime, "sw") == []
    assert execute.apply(runtime, "sw", change, expected_plan_sha256=plan["plan_sha256"])["change_id"] == record["change_id"]
    assert wire.saves == 0 and len(wire.applied_blocks) == 1 and not wire.timers
    assert "synthetic private EXOS diagnostic" not in repr(runtime.store.records())
