"""EOS-SYSTEM-SERVICES through the Admin runtime and EOS transport fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

from fake_eos import FakeEos
from netops_admin import exec_eos, execute
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_eos import make_runtime, request

FIXTURES = Path(__file__).parent / "fixtures" / "eos_eos_system_services"
NTP = "192.0.2.29"
LOG = "192.0.2.30"
DNS = "192.0.2.31"
NTP_SHOW = "show ntp associations | json"
LOG_SHOW = "show logging"
DNS_SHOW = "show ip name-server | json"
HOSTS_SHOW = "show hosts | json"
DIFF_SHOW = "show running-config diffs"
COPY = "copy running-config startup-config"
DEVICE = "lab-ceos"


def fixture(name):
    return (FIXTURES / f"{name}.txt").read_text()


class ServiceDevice(FakeEos):
    def __init__(self):
        super().__init__()
        self.diff = fixture("clean-diff")
        self.readback_denied = False
        self.readback_override = {}
        self.ntp_ready_at = 0
        self.ntp_delay = 4

    def _line(self, line, mode):
        if line == COPY and mode[0] == "exec":
            self.saved = list(self.lines)
            self.saves += 1
            return ""
        if mode[0] == "config":
            command = line.removeprefix("no ").removeprefix("default ")
            families = (f"ntp server {NTP}", f"logging host {LOG}", f"ip name-server vrf default {DNS}",
                        "logging trap", "logging facility", "dns domain")
            family = next((name for name in families if command == name or command.startswith(name + " ")), None)
            if family is not None:
                self.lines = [row for row in self.lines if row != family and not row.startswith(family + " ")]
                if not line.startswith(("no ", "default ")):
                    self.lines.insert(self.lines.index("end"), line)
                if family == families[0]:
                    self.ntp_ready_at = self.uptime + self.ntp_delay
                return ""
        return super()._line(line, mode)

    def query(self, command):
        if command == DIFF_SHOW:
            return "" if self.lines == self.saved else self.diff
        return super().query(command)

    def check_query_status(self, command):
        self.check_queries.append(command)
        if command in self.readback_override:
            answer = self.readback_override[command]
            if isinstance(answer, Exception):
                raise answer
            return answer
        if command == DIFF_SHOW:
            return (1, fixture("ro-diff-denied")) if self.readback_denied else (0, self.query(command))
        if command == NTP_SHOW:
            active = any(line.startswith(f"ntp server {NTP}") for line in self.lines)
            return 0, fixture("settled-ntp" if active and self.uptime >= self.ntp_ready_at else "before-ntp")
        if command == DNS_SHOW:
            prefix = f"ip name-server vrf default {DNS}"
            entry = next((line for line in self.lines if line == prefix or line.startswith(prefix + " ")), None)
            if entry is None:
                return 0, fixture("before-dns")
            priority = entry.removeprefix(prefix).removeprefix(" priority ") or "0"
            return 0, fixture("after-dns").replace('"priority": 0', f'"priority": {priority}')
        if command == LOG_SHOW:
            reply = fixture("after-logging" if f"logging host {LOG}" in self.lines else "before-logging")
            for prefix, label, default in (("logging trap ", "Trap logging: level ", "informational"),
                                           ("logging facility ", "Syslog facility: ", "local4")):
                match = next((line.removeprefix(prefix) for line in self.lines if line.startswith(prefix)), None)
                if match is not None:
                    reply = reply.replace(label + default, label + match)
            return 0, reply
        if command == HOSTS_SHOW:
            reply = fixture("before-hosts")
            name = next((line.removeprefix("dns domain ") for line in self.lines
                         if line.startswith("dns domain ")), "")
            return 0, reply.replace('"domainName": ""', f'"domainName": "{name}"')
        raise AssertionError(f"unexpected check query {command}")


def test_shipped_unmeasured_profile_is_refused_before_device_access(tmp_path):
    # 1.0.13: save, system services and the BGP neighbor were measured live; the MLAG peer profile is still disabled
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device)

    def unexpected_access(_device):
        pytest.fail("the disabled profile must be refused before opening the transport")

    runtime.access_factory = unexpected_access
    before = device.snapshot()
    change = request(op="update", table="mlag-peer", key="global", changes={"peer-address": "192.0.2.123"})
    for call in (execute.preview, execute.apply):
        with pytest.raises(Rejected) as caught:
            call(runtime, DEVICE, change)
        assert caught.value.reason_codes == ["profile_not_measured"]
    assert device.snapshot() == before and device.saves == 0
    assert runtime.store.records() == []


@pytest.mark.parametrize(("table", "key", "changes", "readback"), [
    ("ntp-server", NTP, {"source": "Loopback0"}, NTP_SHOW),
    ("syslog-host", LOG, {}, LOG_SHOW),
    ("dns-server", DNS, {}, DNS_SHOW),
    ("system-services", "system-services",
     {"trap": "warnings", "facility": "local5", "domain-name": "example.test"}, HOSTS_SHOW),
])
def test_preview_confirm_recheck_and_undo(tmp_path, table, key, changes, readback):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device)
    before = device.snapshot()
    req = request(table=table, key=key, op="update" if table == "system-services" else "create", changes=changes,
                  **({"endpoint_impact": key} if table == "system-services" else {}))
    p = execute.preview(runtime, DEVICE, req)
    assert p["result"] == "ready", p
    if table == "system-services":
        assert "dns domain example.test" in p["commands"]
    assert not device.applied_blocks
    with pytest.raises(Rejected, match="approved preview"):
        execute.apply(runtime, DEVICE, req)
    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=p["plan_sha256"])
    assert record["result"] == "confirmed" and not record["reason"], record
    assert "check_identity_passed" in {step["step"] for step in record["steps"]}
    assert device.check_queries.count(readback) >= 3
    assert device.snapshot() != before
    undo = execute.preview_undo(runtime, record["change_id"], "undo EOS-SYSTEM-SERVICES test", issue=True)
    assert undo["result"] == "ready", undo
    if table == "system-services":
        assert "default dns domain" in undo["commands"]
    returned = execute.undo(runtime, record["change_id"], "undo EOS-SYSTEM-SERVICES test", undo["plan_sha256"])
    assert returned["result"] == "confirmed" and not returned["reason"], returned
    assert device.snapshot() == before
    assert device.saved == device.lines and not device.sessions


@pytest.mark.parametrize(("table", "key", "line"), [
    ("dns-server", DNS, f"ip name-server vrf default {DNS}"),
    ("ntp-server", NTP, f"ntp server {NTP} source Loopback0"),
    ("syslog-host", LOG, f"logging host {LOG}"),
])
def test_existing_server_removal_requires_impact(tmp_path, table, key, line):
    device = ServiceDevice()
    device.lines.insert(-1, line)
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    p = execute.preview(runtime, DEVICE, request(table=table, key=key, op="delete", changes={}))
    assert p["reason_codes"] == ["endpoint_impact_required"]
    assert not device.applied_blocks
    req = request(table=table, key=key, op="delete", changes={}, endpoint_impact=key)
    p = execute.preview(runtime, DEVICE, req)
    assert p["result"] == "ready", p
    rec = execute.apply(runtime, DEVICE, req, expected_plan_sha256=p["plan_sha256"])
    assert rec["result"] == "confirmed" and not rec["reason"], rec
    undo = execute.preview_undo(runtime, rec["change_id"], "restore exact test server", issue=True)
    assert undo["result"] == "ready", undo
    execute.undo(runtime, rec["change_id"], "restore exact test server", undo["plan_sha256"])
    assert line in device.lines


@pytest.mark.parametrize(("command", "reply", "code", "table", "key"), [
    (NTP_SHOW, (0, fixture("settled-ntp")[:-5]), "eos_service_readback_unreadable", "ntp-server", NTP),
    (DNS_SHOW, (1, fixture("before-dns")), "eos_service_readback_unreadable", "dns-server", DNS),
    (LOG_SHOW, (0, fixture("after-logging").split("External configuration:")[0]),
     "eos_service_readback_unreadable", "syslog-host", LOG),
    (DNS_SHOW, AccessError("query failed: ssh to switch did not finish within 10.0 seconds"), "eos_service_read_timeout", "dns-server", DNS),
])
def test_invalid_check_output_stops_before_write(tmp_path, command, reply, code, table, key):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device)
    device.readback_override[command] = reply
    preview = execute.preview(runtime, DEVICE, request(table=table, key=key, op="create", changes={}))
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code], preview
    assert not device.applied_blocks


def test_ntp_missing_operational_peer_reverts(tmp_path):
    device = ServiceDevice()
    device.ntp_delay = 120
    runtime = make_runtime(tmp_path, device)
    baseline = device.snapshot()
    req = request(table="ntp-server", key=NTP, op="create", changes={})
    plan = execute.preview(runtime, DEVICE, req)
    assert plan["result"] == "ready", plan
    rec = execute.apply(runtime, DEVICE, req, expected_plan_sha256=plan["plan_sha256"])
    assert rec["result"] == "reverted" and rec["reason"] == "check identity mismatch", rec
    assert device.snapshot() == baseline and not device.sessions


def save_request(**fields):
    return request(table="startup-config", key="startup-config", op="save", changes={}, **fields)


@pytest.mark.parametrize("dirty", [False, True])
def test_standalone_save_uses_a_single_confirmed_copy(tmp_path, dirty):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device)
    if dirty:
        device.lines[-1:-1] = [" ".join(line.split()) for line in fixture("after-config").splitlines()]
    before = device.snapshot()
    req = save_request()
    plan = execute.preview(runtime, DEVICE, req)
    assert plan["result"] == "ready" and plan["return_mechanism"] == "irreversible", plan
    assert plan["inverse_commands"] == 0 and not device.applied_blocks
    assert bool(plan["predicted"]["before"]["diff"]) == dirty
    with pytest.raises(Rejected) as absent:
        execute.apply(runtime, DEVICE, req)
    assert absent.value.reason_codes == ["eos_save_preview_required"]
    rec = execute.apply(runtime, DEVICE, req, expected_plan_sha256=plan["plan_sha256"])
    assert rec["result"] == "confirmed", rec
    assert device.applied_blocks == [[COPY]] and DIFF_SHOW in device.check_queries
    assert device.saved == device.lines and device.snapshot() == before and not device.sessions
    assert execute.apply(runtime, DEVICE, req, expected_plan_sha256=plan["plan_sha256"])["change_id"] == rec["change_id"]
    with pytest.raises(Rejected) as undo:
        execute.preview_undo(runtime, rec["change_id"], "try undo")
    assert undo.value.reason_codes == ["undo_not_applicable"]


def test_redacted_diff_still_binds_secret_only_change(tmp_path):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device, simulate_unmeasured_profiles=True)
    device.lines.insert(-1, "logging host " + LOG)
    device.diff = device.diff.replace(" [context]", " snmp-server community aa ro", 1)
    req = save_request()
    p = execute.preview(runtime, DEVICE, req)
    diff = p["predicted"]["before"]["diff"]
    assert p["result"] == "ready" and " snmp-server [redacted]" in diff
    assert " aa ro" not in "\n".join(diff)
    device.diff = device.diff.replace(" aa ro", " bb ro")
    with pytest.raises(Rejected) as error:
        execute.apply(runtime, DEVICE, req, expected_plan_sha256=p["plan_sha256"])
    assert error.value.reason_codes == ["plan_changed"]
    assert "actual" not in error.value.reason_details[0]
    assert not device.applied_blocks


@pytest.mark.parametrize("failure", ["permission", "truncated", "mismatch", "pending"])
def test_save_refuses_before_copy(tmp_path, failure):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device, simulate_unmeasured_profiles=True)
    device.lines.insert(-1, "logging host " + LOG)
    if failure == "permission":
        device.readback_denied = True
        code = "eos_save_check_denied"
    elif failure == "truncated":
        device.diff = device.diff.rsplit("\n", 2)[0]
        code = "eos_save_diff_unreadable"
    elif failure == "mismatch":
        device.readback_override[DIFF_SHOW] = (0, "")
        code = "eos_save_diff_mismatch"
    else:
        device.sessions["other"] = {"state": "pending"}
        code = "foreign_config_session"
    p = execute.preview(runtime, DEVICE, save_request())
    assert p["result"] == "rejected" and p["reason_codes"] == [code], p
    if failure == "permission":
        assert p["predicted"]["before"]["diff"]
        with pytest.raises(Rejected) as error:
            execute.apply(runtime, DEVICE, save_request(), expected_plan_sha256=p["plan_sha256"])
        assert error.value.reason_codes == [code]
    assert not device.applied_blocks


@pytest.mark.parametrize("fault,code", [
    ("pending", "foreign_config_session"),
    ("disconnected", "eos_save_diff_unreadable"),
])
def test_save_rechecks_sessions_after_admission(tmp_path, fault, code):
    class SaveWire(ServiceDevice):
        def query(self, command):
            if command == exec_eos.QUERY_SESSIONS and runtime.store.running(DEVICE):
                if fault == "disconnected":
                    raise AccessError("synthetic private EOS diagnostic")
                self.sessions["other-operator"] = {"state": "pending"}
            return super().query(command)

    device = SaveWire()
    runtime = make_runtime(tmp_path, device, simulate_unmeasured_profiles=True)
    req = save_request()
    plan = execute.preview(runtime, DEVICE, req)
    assert plan["result"] == "ready"

    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=plan["plan_sha256"])

    assert (record["result"], record["reason_codes"]) == ("rejected", [code])
    assert not device.applied_blocks and device.saves == 0
    assert runtime.store.blocked(DEVICE) is None
    assert "synthetic private EOS diagnostic" not in repr(runtime.store.records())
    if fault == "pending":
        assert device.sessions == {"other-operator": {"state": "pending"}}


def test_save_with_disconnected_check_after_copy_is_blocked_and_never_repeated(tmp_path):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device, simulate_unmeasured_profiles=True)
    req = save_request()
    plan = execute.preview(runtime, DEVICE, req)
    assert plan["result"] == "ready"

    def lose_check(dev, commands):
        assert commands == [COPY]
        dev.readback_override[DIFF_SHOW] = AccessError("synthetic private EOS diagnostic")

    device.on_apply = lose_check
    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=plan["plan_sha256"])

    assert (record["result"], record["reason"]) == ("unknown", "save outcome unverified")
    assert runtime.store.blocked(DEVICE)["change_id"] == record["change_id"]
    assert execute.recover(runtime, DEVICE) == []
    assert execute.apply(runtime, DEVICE, req, expected_plan_sha256=plan["plan_sha256"])["change_id"] == record["change_id"]
    assert device.applied_blocks == [[COPY]] and device.saves == 1 and not device.sessions
    assert "synthetic private EOS diagnostic" not in repr(runtime.store.records())


def test_firmware_warning_does_not_disable_service_or_save(tmp_path):
    device = ServiceDevice()
    device.firmware = "4.36.2F"
    device.lines = [line.replace("EOS-4.36.1F", "EOS-4.36.2F") for line in device.lines]
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device, firmware=device.firmware, simulate_unmeasured_profiles=True)
    requests = [request(table="dns-server", key=DNS, op="create", changes={}, request_id="eos-system-services-dns-fw"),
                save_request(request_id="eos-system-services-save-fw")]
    for req in requests:
        p = execute.preview(runtime, DEVICE, req)
        assert p["result"] == "ready" and p["firmware_support"]["status"] == "untested", p
    assert not device.applied_blocks


def test_dns_priority_update_restores_the_previous_priority(tmp_path):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device)
    create = request(table="dns-server", key=DNS, op="create", changes={"priority": 10},
                     request_id="eos-system-services-dns-initial")
    update = request(table="dns-server", key=DNS, op="update", changes={"priority": 5}, endpoint_impact=DNS,
                     request_id="eos-system-services-dns-priority")

    first = execute.preview(runtime, DEVICE, create)
    assert first["result"] == "ready", first
    result = execute.apply(runtime, DEVICE, create, expected_plan_sha256=first["plan_sha256"])
    assert result["result"] == "confirmed" and not result["reason"], result
    before = device.snapshot()
    second = execute.preview(runtime, DEVICE, update)
    assert second["result"] == "ready" and second["predicted"] == {
        "before": {"priority": "10"}, "after": {"priority": "5"}}, second
    result = execute.apply(runtime, DEVICE, update, expected_plan_sha256=second["plan_sha256"])
    assert result["result"] == "confirmed" and not result["reason"], result
    undo = execute.preview_undo(runtime, result["change_id"], "restore DNS priority", issue=True)
    assert undo["result"] == "ready", undo
    returned = execute.undo(runtime, result["change_id"], "restore DNS priority", undo["plan_sha256"])
    assert returned["result"] == "confirmed" and not returned["reason"]
    assert device.snapshot() == before


def test_recover_never_repeats_an_interrupted_save(tmp_path):
    device = ServiceDevice()
    runtime = make_runtime(tmp_path, device, simulate_unmeasured_profiles=True)
    req = save_request()
    p = execute.preview(runtime, DEVICE, req)
    assert p["result"] == "ready", p
    def interrupt(*_args):
        raise KeyboardInterrupt

    device.on_apply = interrupt
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, DEVICE, req, expected_plan_sha256=p["plan_sha256"])
    assert device.applied_blocks == [[COPY]]
    device.on_apply = None
    [record] = execute.recover(runtime, DEVICE)
    assert record["result"] == "unknown" and record["reason"] == "interrupted; save outcome unverified"
    assert device.applied_blocks == [[COPY]] and device.saves == 0



def test_legacy_domain_statement_is_not_overwritten(tmp_path):
    device = ServiceDevice()
    device.lines.insert(-1, "ip domain-name existing.example")
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device, simulate_unmeasured_profiles=True)
    req = request(table="system-services", key="system-services", op="update",
                  changes={"domain-name": "new.example"}, endpoint_impact="system-services")
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["eos_service_unsupported"], preview
    assert not device.applied_blocks
