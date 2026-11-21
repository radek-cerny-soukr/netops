"""G34 with VM220 FortiADC-KVM 7.6.7 build0676 CLI answers at the transport boundary."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from fake_fortiadc import STANDALONE_HA
from fake_fortiadc_admin import measured
from netops_admin import engine, exec_fortiadc, execute, fortiadc, fortiadc_plan
from netops_admin.errors import Rejected
from test_fortiadc_admin_runtime import make_runtime, request

FIXTURES = Path(__file__).with_name("fixtures") / "fortiadc_g34"
VS = fortiadc_plan.VIRTUAL_SERVERS
RS = fortiadc_plan.REAL_SERVERS
MEMBER = fortiadc_plan.TABLE
SMTP = "LAB_VS_SMTP"
DNS = "LAB_VS_DNS"
TARGET = "NETOPS_TEST_G34_IP"
FQDN = "NETOPS_TEST_G34_DNS"
POOL = "LAB_POOL_SMTP"
POOL_KEY = POOL + ":13"


def capture(name):
    return (FIXTURES / (name + ".txt")).read_bytes().decode()


class Wire:
    def __init__(self, commands=(), before=None, after=None, diagnoses=None, after_diagnoses=None):
        self.credential = SimpleNamespace(login="admin")
        self.check_credential = SimpleNamespace(login="netops-read")
        self.writes = []
        self.checks = []
        self.health_reads = []
        self.answers = {
            "get system status": measured("get_system_status.txt"),
            fortiadc.HA_STATUS: STANDALONE_HA,
            "show system admin": measured("show_system_admin.txt"),
            "show " + VS: measured("show_load-balance_virtual-server.txt"),
            "show " + RS: capture("rs-baseline"),
            "show load-balance pool": capture("pool-baseline"),
        } | (before or {})
        self.original = self.answers.copy()
        self.after = after or {}
        self.commands = commands
        self.diagnoses = {
            SMTP: capture(SMTP),
            DNS: capture(DNS),
        } | (diagnoses or {})
        self.after_diagnoses = after_diagnoses or {}

    def snapshot(self):
        return exec_fortiadc.snapshot(self)

    def query(self, command):
        return self.answers[command]

    def diagnose_query(self, command):
        self.health_reads.append(command)
        name = command.rpartition(" ")[2]
        if len(self.writes) == 1 and name in self.after_diagnoses:
            return self.after_diagnoses[name]
        return self.diagnoses[name]

    def check_query(self, command):
        self.checks.append(command)
        return self.answers[command]

    def apply(self, commands, _spec):
        expected = self.commands[len(self.writes)]
        assert commands == expected
        self.writes.append(commands)
        self.answers = (self.original | self.after) if len(self.writes) == 1 else self.original.copy()


def confirm_and_return(tmp_path, wire, req, observation):
    runtime = make_runtime(tmp_path, wire)
    preview = execute.preview(runtime, "adc", req)
    assert preview["result"] == "ready", preview
    assert not wire.writes and wire.answers == wire.original
    assert wire.checks == [observation]
    applied = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", applied
    assert "check_identity_passed" in [step["step"] for step in applied["steps"]]
    assert wire.checks == [observation] * 3
    undo_preview = execute.preview_undo(runtime, applied["change_id"], "fixture return")
    assert undo_preview["result"] == "ready", undo_preview
    assert len(wire.writes) == 1
    returned = execute.undo(runtime, applied["change_id"], "fixture return")
    assert returned["result"] == "confirmed", returned
    assert len(wire.writes) == 2 and wire.answers == wire.original
    assert wire.checks == [observation] * 6
    return preview


def server_steps(table, name, *fields):
    return ["config " + table, 'edit "%s"' % name, *fields, "next", "end"]


def test_g03_virtual_server_round_trip(tmp_path):
    # Both answers are the measured targeted show for the same VS.
    wire = Wire([server_steps(VS, SMTP, "set status maintain"), server_steps(VS, SMTP, "set status enable")],
                before={"show " + VS: capture("vs-smtp-baseline")},
                after={"show " + VS: capture("vs-maintain")})
    result = confirm_and_return(tmp_path, wire, request(table=VS, key=SMTP, changes={"status": "maintain"}),
                                "show " + VS)
    assert result["predicted"] == {"before": {}, "after": {"status": "maintain"}}
    assert fortiadc.vs_stat_command(SMTP) in wire.health_reads


def test_g03_refuses_missing_runtime_and_only_warns_on_untested_firmware(tmp_path):
    wire = Wire()
    wire.answers["get system status"] = wire.answers["get system status"].replace("v7.6.7", "v7.6.8")
    req = request(table=VS, key=SMTP, changes={"status": "disable"})
    runtime = make_runtime(tmp_path, wire)
    preview = execute.preview(runtime, "adc", req)
    assert preview["result"] == "ready"
    assert preview["firmware_support"]["status"] == "untested"
    wire.diagnoses[SMTP] = capture("absent-vs")
    assert execute.preview(runtime, "adc", req)["result"] == "rejected"
    assert not wire.writes


@pytest.mark.parametrize(("name", "changes", "fields", "answer"), [
    (TARGET, {"ip": "192.0.2.11", "status": "enable"}, ["set ip 192.0.2.11", "set status enable"], "real-ip"),
    (FQDN, {"type": "fqdn", "fqdn": "backend.g34.example", "status": "disable"},
     ["set type fqdn", 'set fqdn "backend.g34.example"', "set status disable"], "real-fqdn"),
])
def test_g05_new_real_server_round_trip(tmp_path, name, changes, fields, answer):
    wire = Wire([server_steps(RS, name, *fields), ["config " + RS, 'delete "%s"' % name, "end"]],
                after={"show " + RS: capture(answer)})
    confirm_and_return(tmp_path, wire, request(op="create", table=RS, key=name, changes=changes), "show " + RS)


def test_g05_rejects_mismatched_address_type_and_refuses_deletion_while_referenced():
    wire = Wire(before={"show " + RS: capture("real-ip"), "show load-balance pool": capture("pools-with-members")})
    snapshot = wire.snapshot().encode()
    with pytest.raises(Rejected, match="needs an IPv4 address"):
        engine.build_plan("fortiadc", snapshot,
                          request(op="create", table=RS, key="NEWR", changes={"fqdn": "backend.example"}))
    with pytest.raises(Rejected, match="referenced"):
        engine.build_plan("fortiadc", snapshot, request(op="delete", table=RS, key=TARGET, changes={}), undo=True)
    assert not wire.writes


def test_g04_checks_both_pools_and_returns_real_server_maintenance(tmp_path):
    wire = maintenance_wire()
    result = confirm_and_return(tmp_path, wire, request(table=RS, key=TARGET, changes={"status": "maintain"}),
                                "show " + RS)
    assert any(SMTP in line and "healthy enabled" in line for line in result["prechecks"])
    assert any(DNS in line and "healthy enabled" in line for line in result["prechecks"])
    assert set(wire.health_reads) == {fortiadc.vs_stat_command(name) for name in (SMTP, DNS)}


@pytest.mark.parametrize("bad", ["absent-vs", "diagnose_vs_stat_LAB_VS_SMTP.stderr"])
def test_g04_rejects_incomplete_or_unhealthy_data_in_second_pool(tmp_path, bad):
    wire = maintenance_wire()
    wire.diagnoses[SMTP] = (capture(bad) if bad == "absent-vs" else measured(bad + ".txt"))
    runtime = make_runtime(tmp_path, wire)
    result = execute.preview(runtime, "adc", request(table=RS, key=TARGET, changes={"status": "disable"}))
    assert result["result"] == "rejected"
    assert {fortiadc.vs_stat_command(name) for name in (SMTP, DNS)} <= set(wire.health_reads)
    assert not wire.writes


def maintenance_wire():
    return Wire([server_steps(RS, TARGET, "set status maintain"), server_steps(RS, TARGET, "set status enable")],
                before={"show " + RS: capture("real-ip"), "show load-balance pool": capture("pools-with-members")},
                after={"show " + RS: capture("real-maintain")},
                diagnoses={name: capture("runtime-g04-before-" + name) for name in (DNS, SMTP)},
                after_diagnoses={name: capture("runtime-g04-maintain-" + name) for name in (DNS, SMTP)})


def member_steps(*fields):
    return ["config load-balance pool", 'edit "LAB_POOL_SMTP"', "config pool_member", "edit 13",
            *fields, "next", "end", "next", "end"]


def test_c05_updates_weight_port_cookie_and_restores_defaults(tmp_path):
    command = "show load-balance pool " + POOL
    original, changed = capture("pool-member-before"), capture("pool-member-update")
    wire = Wire([member_steps("set pool_member_service_port 2526", 'set pool_member_cookie "g34cookie"',
                              "set pool_member_weight 7"),
                 member_steps("set pool_member_service_port 2525", "set pool_member_weight 1",
                              'set pool_member_cookie "rs13"')],
                before={command: original, "show load-balance pool": original, "show " + RS: capture("real-ip")},
                after={command: changed, "show load-balance pool": changed})
    confirm_and_return(tmp_path, wire, request(table=MEMBER, key=POOL_KEY, changes={
        "pool-member-weight": 7, "pool-member-service-port": 2526, "pool-member-cookie": "g34cookie",
    }), command)


def test_c05_refuses_a_truncated_check_account_listing(tmp_path):
    command = "show load-balance pool " + POOL
    original = capture("pool-member-before")
    wire = Wire(before={command: original[:original.rfind("end")], "show load-balance pool": original})
    runtime = make_runtime(tmp_path, wire)
    result = execute.preview(runtime, "adc", request(table=MEMBER, key=POOL_KEY,
                                                     changes={"pool-member-weight": 7}))
    assert result["result"] == "rejected"
    assert command in wire.checks and not wire.writes


def test_c05_active_port_precheck_uses_health_of_other_members(tmp_path):
    command = "show load-balance pool " + POOL
    pools = capture("pools-with-members")
    wire = Wire(before={command: pools, "show load-balance pool": pools, "show " + RS: capture("real-ip")},
                diagnoses={SMTP: capture("runtime-g04-before-" + SMTP)})
    runtime = make_runtime(tmp_path, wire)
    req = request(table=MEMBER, key=POOL_KEY, changes={"pool-member-service-port": 2526})
    assert execute.preview(runtime, "adc", req)["result"] == "ready"
    wire.diagnoses[SMTP] = measured("diagnose_vs_stat_LAB_VS_SMTP.stderr.txt")
    refused = execute.preview(runtime, "adc", req)
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["no_healthy_member"]
    assert wire.health_reads == [fortiadc.vs_stat_command(SMTP)] * 2
    assert not wire.writes
