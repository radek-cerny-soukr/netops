from pathlib import Path
import re

import pytest
from fake_fortios import FakeFortiOS, quoted
from test_execute import make_runtime, request, steps
from test_mcp_server import arguments, call, mcp_server

from netops_admin import engine, exec_fortios, execute, fortios
from netops_admin.errors import Rejected
from netops_core.fortios import tokenize


FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_g17"
SERIAL = "S000SSSS00000001"
KEY = SERIAL + ":port5"


def capture(name):
    return (FIXTURES / (name + ".txt")).read_text()


class FortiSwitchLab(FakeFortiOS):
    firmware = ("7.6.8", "3744")

    def __init__(self):
        super().__init__()
        self.port_fields = {}
        self.stats_override = None
        self.mac_override = None
        self.ignore_operational_status = False
        self.lldp_override = None

    def port_config(self):
        marker = '            edit "port5"\n'
        lines = "".join(f"                set {key} {quoted(value) if key == 'description' else value}\n"
                        for key, value in self.port_fields.items())
        return capture("config").replace(marker, marker + lines)

    def snapshot(self):
        return super().snapshot() + self.port_config()

    def _run(self, lines, automatic=False):
        if lines[0].strip() != "config " + fortios.MANAGED_SWITCH:
            return super()._run(lines, automatic)
        tokens = [tokenize(line.strip()) for line in lines]
        assert tokens[1:4] == [["edit", SERIAL], ["config", "ports"], ["edit", "port5"]]
        assert tokens[-4:] == [["next"], ["end"], ["next"], ["end"]]
        for action, name, *values in tokens[4:-4]:
            if action == "set" and values != ["up"]:
                self.port_fields[name] = values[0]
            else:
                assert action == "unset" or (name == "status" and values == ["up"])
                self.port_fields.pop(name, None)
        return len(lines)

    def check_query(self, command):
        if command == f"show {fortios.MANAGED_SWITCH} {SERIAL}":
            return self.port_config()
        prefix = exec_fortios.SWITCH_INFO
        if command == f"{prefix} trunk status {SERIAL}":
            return capture("trunk")
        if command == f"{prefix} lldp neighbors-summary {SERIAL}":
            return self.lldp_override if self.lldp_override is not None else capture("lldp")
        if command == f"{prefix} mac-table {SERIAL}":
            return self.mac_override if self.mac_override is not None else capture("mac")
        if command.startswith(f"{prefix} port-stats {SERIAL} "):
            port = command.rsplit(" ", 1)[1]
            if self.stats_override is not None:
                return self.stats_override
            if port == "port5" and self.port_fields.get("status") == "down" and not self.ignore_operational_status:
                down_capture = FIXTURES / "port5-down.txt"
                if down_capture.exists():
                    return down_capture.read_text()
                return capture(port).replace("SW Admin up", "SW Admin down")
            return capture(port)
        raise AssertionError(command)


def ask(*, table=fortios.SWITCH_PORT, key=KEY, changes=None, **fields):
    return request(table=table, key=key, op="update", changes=changes or {"description": "G17 fixture"}, **fields)


@pytest.mark.parametrize("changes", [{"description": 'G17 "quoted" port'}, {"status": "down"}])
def test_port_update_preview_apply_readback_and_undo(tmp_path, changes):
    lab = FortiSwitchLab()
    original = lab.snapshot()
    runtime = make_runtime(tmp_path, lab)
    req = ask(changes=changes)
    preview = execute.preview(runtime, "lab", req)
    assert preview["result"] == "ready"
    assert preview["firmware_support"]["status"] == "tested"
    assert lab.applied_blocks == []
    if "description" in changes:
        assert any("set description " in line for line in preview["commands"])
    with pytest.raises(Rejected) as exc:
        execute.apply(runtime, "lab", req)
    assert exc.value.reason_codes == ["plan_changed"]
    plan = execute.preview(runtime, "lab", req)
    result = execute.apply(runtime, "lab", req, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert lab.port_fields == changes
    assert engine.verify(result["plan"], lab.snapshot().encode())["result"] == "match"
    undo = execute.preview_undo(runtime, result["change_id"], "Restore port", issue=True)
    assert undo["result"] == "ready", undo
    record = execute.undo(runtime, result["change_id"], "Restore port", expected_plan_sha256=undo["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert lab.snapshot() == original
    assert not lab.stitches and not lab.actions and not lab.triggers


def test_port_undo_does_not_write_when_the_last_port_read_is_incomplete(tmp_path):
    class SwitchWire(FortiSwitchLab):
        fail_prewrite = False

        def check_query(self, command):
            if self.fail_prewrite and self.stitches and command == f"{exec_fortios.SWITCH_INFO} port-stats {SERIAL} port5":
                return capture("port5").split("output")[0]
            return super().check_query(command)

    lab = SwitchWire()
    runtime = make_runtime(tmp_path, lab)
    wanted = ask()
    plan = execute.preview(runtime, "lab", wanted)
    assert plan["result"] == "ready"
    applied = execute.apply(runtime, "lab", wanted, expected_plan_sha256=plan["plan_sha256"])
    assert applied["result"] == "confirmed"
    modified = lab.snapshot()
    reason = "Restore port description"
    undo = execute.preview_undo(runtime, applied["change_id"], reason, issue=True)
    assert undo["result"] == "ready"
    writes = len(lab.applied_blocks)
    lab.fail_prewrite = True

    record = execute.undo(runtime, applied["change_id"], reason, expected_plan_sha256=undo["plan_sha256"])

    assert (record["result"], record["reason"]) == ("reverted", "managed switch port state changed")
    assert "safeguard_removed" in steps(record) and "change_start" not in steps(record)
    assert not any(f"config {fortios.MANAGED_SWITCH}" in block for block in lab.applied_blocks[writes:])
    assert lab.snapshot() == modified and not lab.stitches and not lab.actions and not lab.triggers
    assert runtime.store.blocked("lab") is None


def test_bounce_through_mcp_proves_the_down_and_restored_states(tmp_path, monkeypatch):
    lab = FortiSwitchLab()
    runtime = make_runtime(tmp_path, lab)
    monkeypatch.setattr(mcp_server, "configured_runtime", lambda: runtime)
    args = arguments(table=fortios.SWITCH_BOUNCE, key=KEY, op="update", changes={"status": "down"})
    before = lab.snapshot()
    plan = call("admin_preview", args)
    assert plan["result"] == "ready" and not lab.applied_blocks
    assert plan["firmware_support"]["status"] == "tested"
    assert call("admin_apply", args)["reason_codes"] == ["plan_changed"]
    result = call("admin_apply", {**args, "expected_plan_sha256": plan["plan_sha256"]})
    assert result["result"] == "confirmed", result
    assert result["readback"] == {"before": {"admin": "up", "link": "down"},
                                  "down": {"admin": "down", "link": "down"},
                                  "after": {"admin": "up", "link": "down"}}
    assert lab.snapshot() == before
    assert not lab.stitches


def test_bounce_stays_unconfirmed_when_the_switch_never_shows_down(tmp_path):
    lab = FortiSwitchLab()
    lab.ignore_operational_status = True
    start = lab.clock
    runtime = make_runtime(tmp_path, lab)
    runtime.monotonic = lambda: (lab.clock - start).total_seconds()
    req = ask(table=fortios.SWITCH_BOUNCE, changes={"status": "down"})
    plan = exec_fortios.preview(runtime, "lab", "port-bounce", req)
    result = exec_fortios.apply(runtime, "lab", "port-bounce", req, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "reverted"
    assert result["reason"] == "cycle effect unverified"
    assert not lab.port_fields and not lab.stitches


@pytest.mark.parametrize(("port", "protected", "code"), [
    ("port1", {}, "port_protected"),
    ("port3", {"interface": ["port3"]}, "port_protected"),
    ("port4", {"interface": [SERIAL + ":port4"]}, "port_protected"),
    ("port4", {}, "endpoint_impact_required"),
])
def test_bounce_refuses_protected_uplink_or_active_port_without_impact(tmp_path, port, protected, code):
    lab = FortiSwitchLab()
    runtime = make_runtime(tmp_path, lab, protected=protected)
    req = ask(table=fortios.SWITCH_BOUNCE, key=SERIAL + ":" + port, changes={"status": "down"})
    result = exec_fortios.preview(runtime, "lab", "port-bounce", req)
    assert result["result"] == "rejected" and result["reason_codes"] == [code]
    assert not lab.applied_blocks


@pytest.mark.parametrize("answer", [
    "command parse error before 'switch-info'\nCommand fail. Return code -61\n",
    capture("port5").split("output")[0],
    re.sub(r"^S[A-Z0-9]+:", "S111111111111111:", capture("port5"), flags=re.M),
])
def test_refused_incomplete_or_wrong_switch_readback_blocks_preview(tmp_path, answer):
    lab = FortiSwitchLab()
    lab.stats_override = answer
    result = execute.preview(make_runtime(tmp_path, lab), "lab", ask())
    assert result["result"] == "rejected" and result["reason_codes"] == ["state_unreadable"]
    assert not lab.applied_blocks


def test_incomplete_mac_table_blocks_inactive_port_write(tmp_path):
    lab = FortiSwitchLab()
    lab.mac_override = capture("mac").replace("Total Displayed: 9", "Total Displayed: 10")
    result = execute.preview(make_runtime(tmp_path, lab), "lab", ask())
    assert result["result"] == "rejected" and result["reason_codes"] == ["state_unreadable"]
    assert not lab.applied_blocks


def test_scope_digest_includes_unmanaged_port_attributes():
    lab = FortiSwitchLab()
    before = lab.snapshot()
    plan = engine.build_plan("fortios", before.encode(), ask(), device="lab")
    lab.port_fields.update(description="G17 fixture", speed="1000auto")
    verdict = engine.verify(plan, lab.snapshot().encode())
    assert verdict["object_matches"] and verdict["result"] == "mismatch"


def test_active_endpoint_impact_is_bound_but_cannot_authorize_a_bridge(tmp_path):
    lab = FortiSwitchLab()
    runtime = make_runtime(tmp_path, lab)
    endpoint = SERIAL + ":port4"
    req = ask(table=fortios.SWITCH_BOUNCE, key=endpoint, changes={"status": "down"}, endpoint_impact=endpoint)
    result = exec_fortios.preview(runtime, "lab", "port-bounce", req)
    assert result["reason_codes"] == ["port_protected"]
    # Derive a station neighbor from the captured port4 row, retaining the live column format.
    lab.lldp_override = capture("lldp").replace("BRWS", "S   ")
    result = exec_fortios.preview(runtime, "lab", "port-bounce", req)
    assert result["result"] == "ready", result
    assert result["cycle_state"] == {"admin": "up", "link": "up"}
    assert not lab.applied_blocks


def test_config_readback_with_missing_port_or_truncation_is_unreadable():
    text = capture("config")
    for answer in (text.replace('"port5"', '"port99"'), text.rsplit("end", 1)[0]):
        with pytest.raises(Rejected) as refused:
            fortios.shown_switch_port(answer, KEY)
        assert refused.value.reason_codes == ["state_unreadable"]



def test_readonly_switch_controller_permission_refuses_before_safeguard(tmp_path):
    lab = FortiSwitchLab()
    lab.snapshot_extra = [
        "config system admin",
        '    edit "netops-rw"',
        '        set accprofile "netops-write"',
        "    next",
        "end",
        "config system accprofile",
        '    edit "netops-write"',
        "        set wifi read",
        "    next",
        "end",
    ]
    result = execute.preview(make_runtime(tmp_path, lab), "lab", ask())
    assert result["result"] == "rejected"
    assert result["reason_codes"] == ["fortiswitch_write_permission_required"]
    assert not lab.applied_blocks
