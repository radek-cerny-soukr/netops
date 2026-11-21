"""Replay measured service configuration and operational readbacks from NX-OS 9.3(12)."""
import json
from pathlib import Path

import pytest

from fake_nxos import FakeNxos
from netops_admin import engine, exec_nxos, execute, nxos
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_nxos import make_runtime, request as admin_request

FIXTURES = Path(__file__).parent / "fixtures" / "nxos_g104"
DEVICE = "lab-nxos"
COPY = "copy running-config startup-config"
CASES = [
    ("ntp-server", "198.51.100.10", {"vrf": "management"}, "ntp-config", "ntp-peers",
     "ntp server 198.51.100.10 use-vrf management"),
    ("ntp-source", "global", {"source-interface": "loopback104"}, "ntp-config", "ntp-source",
     "ntp source-interface loopback104"),
    ("syslog-server", "198.51.100.20", {"severity": 5, "vrf": "management"}, "syslog-config", "logging-servers",
     "logging server 198.51.100.20 5 use-vrf management"),
    ("syslog-source", "global", {"source-interface": "loopback104"}, "syslog-config", "logging-source",
     "logging source-interface loopback104"),
    ("dns-server", "198.51.100.30", {"vrf": "management"}, "dns-config", "hosts",
     "ip name-server 198.51.100.30 use-vrf management"),
    ("dns-domain", "default", {"domain": "g104.example"}, "dns-config", "hosts", "ip domain-name g104.example"),
]


def measured(name):
    return (FIXTURES / (name + ".txt")).read_text(encoding="utf-8")


class ServiceDevice(FakeNxos):
    def __init__(self, case=None, transport="configured"):
        super().__init__()
        self.case = case
        self.transport = transport
        self.body.extend(["interface loopback104", "  ip address 192.0.2.104/32"])
        self.saved = self._config()
        self.readback = None
        self.diff = measured("configured-diff")

    def measured_statement(self):
        if self.transport == "default" and self.case[0].endswith("-server"):
            server = self.case[1]
            return next(line for line in measured("default-" + self.case[3]).splitlines() if server in line)
        return self.case[-1]

    def _config_line(self, words, mode):
        line = " ".join(words)
        if self.case:
            statement = self.measured_statement()
            if line == self.case[-1]:
                assert statement in measured(self.transport + "-" + self.case[3]).splitlines()
                self.body.append(statement)
                return ""
            if line.startswith("no "):
                removals = (
                    "no " + statement,
                    "no logging source-interface",
                    "no logging server " + self.case[1],
                )
                if line in removals and statement in self.body:
                    self.body.remove(statement)
                    return ""
        return super()._config_line(words, mode)

    def _read(self, command):
        if self.readback is not None:
            if isinstance(self.readback, Exception):
                raise self.readback
            return self.readback
        state = self.transport if self.measured_statement() in self.body else "base"
        return 0, measured(state + "-" + self.case[4])

    def check_query_status(self, command):
        assert self.case and command == exec_nxos.SERVICE_COMMANDS[self.case[0]]
        self.check_queries.append(command)
        return self._read(command)

    def query_status(self, command):
        if command == "show hosts":
            self.queries.append(command)
            return self._read(command)
        if command == exec_nxos.QUERY_DIFF:
            self.queries.append(command)
            return 0, "" if self._config() == self.saved else self.diff
        return super().query_status(command)


def operation(case, **fields):
    table, key, changes, *_ = case
    return admin_request(table=table, key=key, changes=changes,
                         op="create" if table.endswith("-server") else "update", **fields)


@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
def test_service_preview_confirmation_and_actual_return(tmp_path, case):
    device = ServiceDevice(case)
    runtime = make_runtime(tmp_path, device)
    req = operation(case)
    baseline = device._config()
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "ready", preview
    assert not device.applied_blocks
    with pytest.raises(Rejected) as error:
        execute.apply(runtime, DEVICE, req)
    assert error.value.reason_codes == ["plan_changed"]
    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record["reason"], record["differences"])
    assert device.measured_statement() in device.body
    inverse = execute.preview_undo(runtime, record["change_id"], "Test return", issue=True)
    assert inverse["result"] == "ready", inverse
    returned = execute.undo(runtime, record["change_id"], "Test return", expected_plan_sha256=inverse["plan_sha256"])
    assert returned["result"] == "confirmed", (returned["reason"], returned["differences"])
    assert device._config() == baseline == device.saved
    assert not (device.checkpoints or device.files or device.jobs or device.schedules)


@pytest.mark.parametrize("case", CASES[::2], ids=["ntp", "syslog", "dns"])
def test_wave6_last_service_server_requires_endpoint_impact(tmp_path, case):
    device = ServiceDevice(case)
    device.body.append(device.measured_statement())
    device.saved = device._config()
    runtime = make_runtime(tmp_path, device)
    table, key, *_ = case
    fields = dict(table=table, key=key, changes={}, op="delete")
    preview = execute.preview(runtime, DEVICE, admin_request(**fields))
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["endpoint_impact_required"]
    assert not device.applied_blocks

    approved = admin_request(**fields, endpoint_impact=key)
    preview = execute.preview(runtime, DEVICE, approved)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, DEVICE, approved, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert device.measured_statement() not in device.body


@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
def test_inconsistent_or_partial_readback_refuses_without_write(tmp_path, case):
    device = ServiceDevice(case)
    runtime = make_runtime(tmp_path, device)
    device.readback = 0, measured("configured-" + case[4]).splitlines()[0] + "\n"
    result = execute.preview(runtime, DEVICE, operation(case))
    assert result["result"] == "rejected" and not device.applied_blocks, result
    assert result["reason_codes"] == ["nxos_service_readback_unreadable"]


@pytest.mark.parametrize("failure,code", [
    ((30, "% Permission denied for the role"), "nxos_service_readback_unreadable"),
    (AccessError("connection timed out"), "nxos_service_read_timeout"),
])
def test_readback_differentiates_denial_and_timeout(tmp_path, failure, code):
    device = ServiceDevice(CASES[0])
    runtime = make_runtime(tmp_path, device)
    device.readback = failure
    result = execute.preview(runtime, DEVICE, operation(CASES[0]))
    assert result["result"] == "rejected" and not device.applied_blocks, result
    assert result["reason_codes"] == [code]


@pytest.mark.parametrize("case", [CASES[0], CASES[2], CASES[4]], ids=["ntp", "logging", "dns"])
def test_default_transport_is_implicit_in_prediction_and_readback(case):
    device = ServiceDevice(case, "default")
    device.body.append(device.measured_statement())
    plan = {"table": case[0], "key": case[1], "firmware": "9.3(12)"}
    state = exec_nxos.observe_service(device, plan)
    assert engine.observed_state(plan | {"platform": "nxos"}, state) == {}


def test_unmanaged_ntp_key_is_preserved_without_returning_its_value(tmp_path):
    device = ServiceDevice(CASES[0])
    device.body.append(CASES[0][-1] + " key 4")
    device.saved = device._config()
    runtime = make_runtime(tmp_path, device)
    req = admin_request(table="ntp-server", key=CASES[0][1], op="delete", changes={})
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["reason_codes"] == ["nxos_service_unsupported"]
    assert " key 4" not in json.dumps(preview) and not device.applied_blocks


def test_source_protection_and_unconfigured_vrf():
    device = ServiceDevice(CASES[1])
    with pytest.raises(Rejected) as protected:
        engine.build_plan("nxos", device.snapshot().encode(), operation(CASES[1]),
                          protected={"interface": ["Loopback104"]})
    assert protected.value.reason_codes == ["port_protected"]
    req = admin_request(table="dns-server", key="missing/198.51.100.30", op="create", changes={})
    with pytest.raises(Rejected) as absent:
        engine.build_plan("nxos", device.snapshot().encode(), req)
    assert absent.value.reason_codes == ["nxos_service_unsupported"]


def test_untested_release_warns_for_services_and_save(tmp_path):
    device = ServiceDevice(CASES[0])
    device.firmware = "9.3(11)"
    device.body = [line.replace("9.3(12)", device.firmware) for line in device.body]
    device.saved = device._config()
    runtime = make_runtime(tmp_path, device, firmware=device.firmware)
    for req in (operation(CASES[0], request_id="g104-untested-ntp"), save_request()):
        preview = execute.preview(runtime, DEVICE, req)
        assert preview["result"] == "ready", preview
        assert preview["firmware_support"]["status"] == "untested"
    assert not device.applied_blocks


def save_request():
    return admin_request(table="startup-config", key="startup-config", op="save", changes={})


@pytest.mark.parametrize("dirty", [False, True])
def test_standalone_save_rechecks_and_copies_only_after_approval(tmp_path, dirty):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device)
    if dirty:
        device.body.extend(measured("configured-ntp-config").splitlines())
    req = save_request()
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "ready" and not device.applied_blocks, preview
    diff = preview["predicted"]["before"]["diff"]
    assert bool(diff) == dirty
    if dirty:
        assert "+ ip domain-name g104.example" in diff and "+   ip address 192.0.2.104/32" in diff
    with pytest.raises(Rejected) as error:
        execute.apply(runtime, DEVICE, req)
    assert error.value.reason_codes == ["nxos_save_preview_required"]
    original_running = device._config()
    device.advance(2)  # NX-OS snapshot time changes between preview and apply
    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record["reason"]
    assert device._config() == original_running == device.saved
    assert device.applied_blocks == [[COPY]] and device.scheduler_enabled
    with pytest.raises(Rejected) as error:
        execute.preview_undo(runtime, record["change_id"], "Check irreversible kind")
    assert error.value.reason_codes == ["undo_not_applicable"]


def test_save_masks_credentials_and_digest_detects_change_after_approval(tmp_path):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device)
    device.body.append("ip domain-name g104.example")
    device.diff = device.diff.replace("  [redacted]", "  snmp-server community TEST_SECRET rw", 1)
    req = save_request()
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "ready" and "TEST_SECRET" not in json.dumps(preview)
    device.diff = device.diff.replace("TEST_SECRET", "TEST_VALUE2")
    with pytest.raises(Rejected) as error:
        execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert error.value.reason_codes == ["plan_changed"] and not device.applied_blocks


def test_save_keeps_ordinary_changes_visible_and_masks_other_credential_shapes():
    text = measured("configured-diff")
    text = text.replace("  [redacted]", "  snmp-server user test auth md5 z priv y localizedV2key", 1)
    text = text.replace("+ ip domain-name g104.example", "+   description Maintenance uplink")
    text = text.replace("+ ip name-server 198.51.100.30 use-vrf management", "+   channel-group 4 mode active")
    text = text.replace("+ ntp server 198.51.100.10 use-vrf management", "+ ntp server 192.0.2.4 key 1")
    diff = exec_nxos.parse_save_diff(text)["diff"]
    assert "+   description Maintenance uplink" in diff
    assert "+   channel-group 4 mode active" in diff
    assert "+ [redacted]" in diff
    assert all("priv y" not in line and "key 1" not in line for line in diff)
    assert "+   description Maintenance uplink" not in exec_nxos.parse_save_diff(text, secrets=("Maintenance",))["diff"]


@pytest.mark.parametrize("node", ["b04-nx-a", "b04-nx-b"])
def test_b04_existing_syslog_source_baseline(node):
    assert exec_nxos._source_interface(nxos.SYSLOG_SOURCE, measured(node + "-logging-source")) == {}


def test_save_rejects_truncated_context_diff(tmp_path):
    device = ServiceDevice()
    device.body.append("ip domain-name g104.example")
    device.diff = device.diff[:device.diff.index("+ ip domain-name")]
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, DEVICE, save_request())
    assert preview["reason_codes"] == ["nxos_save_diff_unreadable"] and not device.applied_blocks


def test_save_external_deletion_uses_the_old_section(tmp_path):
    device = ServiceDevice()
    device.body.append(CASES[2][-1])
    device.saved = device._config()
    device.body.remove(CASES[2][-1])
    device.diff = measured("removed-diff")
    runtime = make_runtime(tmp_path, device)
    req = save_request()
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "ready" and not device.applied_blocks, preview
    assert "- " + CASES[2][-1] in preview["predicted"]["before"]["diff"]
    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed" and device.applied_blocks == [[COPY]]
    assert device.saved == device._config()
