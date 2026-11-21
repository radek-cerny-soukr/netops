from pathlib import Path
import re

import pytest

from fake_fortios import quoted
from test_execute import make_runtime
from test_fortios_g17 import KEY, SERIAL, FortiSwitchLab, ask
from test_mcp_server import arguments, call, mcp_server

from netops_admin import engine, exec_fortios, execute, fortios
from netops_admin.errors import Rejected
from netops_core.fortios import tokenize


FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_g18"
POE_RESET = f"execute switch-controller poe-reset {SERIAL} port5"
POWERED = (FIXTURES / "poe-powered.txt").read_text().replace("S108EPXXXXXXXXXX", SERIAL).replace("Port(2)", "Port(5)")
POWER_OFF = POWERED.replace("Delivering Power", "Searching").replace("6.40W", "0.00W").replace("120mA", "0mA")
PORT5 = re.compile(r'(?ms)(^            edit "port5"\n)(.*?)(^            next$)')


class ManagedSwitch(FortiSwitchLab):
    def __init__(self, poe_answers=(), *, reset_readback=POWER_OFF):
        super().__init__()
        self.config = (FIXTURES / "managed-vlans.txt").read_text()
        self.interfaces = (FIXTURES / "interfaces.txt").read_text()
        self.port_fields = {words[1]: words[2:] for line in PORT5.search(self.config)[2].splitlines()
                            if (words := tokenize(line.strip()))}
        self.poe_answers = list(poe_answers)
        self.reset_readback = reset_readback
        self.resets = 0

    def port_config(self):
        fields = "".join(f"                set {name} "
                         + (" ".join(quoted(value) for value in values) if name not in fortios.SWITCH_OPTIONS
                            else values[0]) + "\n" for name, values in self.port_fields.items())
        return PORT5.sub(lambda match: match[1] + fields + match[3], self.config)

    def snapshot(self):
        return super().snapshot() + self.interfaces

    def _run(self, lines, automatic=False):
        if lines == [POE_RESET]:
            self.resets += 1
            if self.reset_readback is not None:
                self.poe_answers = [self.reset_readback, POWERED]
            return 1
        if lines[0].strip() != "config " + fortios.MANAGED_SWITCH:
            return super()._run(lines, automatic)
        tokens = [tokenize(line.strip()) for line in lines]
        assert tokens[1:4] == [["edit", SERIAL], ["config", "ports"], ["edit", "port5"]]
        assert tokens[-4:] == [["next"], ["end"], ["next"], ["end"]]
        for op, name, *values in tokens[4:-4]:
            if op == "unset" or (name, values) in (("poe-status", ["enable"]), ("allowed-vlans-all", ["disable"])):
                self.port_fields.pop(name, None)
            else:
                assert op == "set"
                self.port_fields[name] = values
        return len(lines)

    def check_query(self, command):
        if command == f"{exec_fortios.SWITCH_INFO} poe detail {SERIAL} port5":
            if len(self.poe_answers) > 1:
                return self.poe_answers.pop(0)
            if self.poe_answers:
                answer = self.poe_answers[0]
                if isinstance(answer, Exception):
                    raise answer
                return answer
            return (FIXTURES / "poe-port.txt").read_text()
        if command == f"{exec_fortios.SWITCH_INFO} port-stats {SERIAL} port5" and self.stats_override is None:
            return (FIXTURES / "port5.txt").read_text()
        return super().check_query(command)


@pytest.mark.parametrize(("changes", "expected", "commands", "poe"), [
    ({"vlan": "host02"}, {"vlan": "host02"}, ['set vlan "host02"'], False),
    ({"allowed-vlans": ["quarantine", "host02"], "untagged-vlans": ["quarantine", "host02"]},
     {"allowed-vlans": "host02 quarantine", "untagged-vlans": "host02 quarantine"},
     ['set allowed-vlans "host02" "quarantine"', 'set untagged-vlans "host02" "quarantine"'], False),
    ({"allowed-vlans-all": "enable"}, {"allowed-vlans-all": "enable"}, ["set allowed-vlans-all enable"], False),
    ({"allowed-vlans": [], "untagged-vlans": []}, {},
     ["unset untagged-vlans", "unset allowed-vlans"], False),
    ({"poe-status": "disable"}, {"poe-status": "disable"}, ["set poe-status disable"], True),
])
def test_port_update_apply_and_exact_undo(tmp_path, changes, expected, commands, poe):
    lab = ManagedSwitch([POWERED.replace("Delivering Power", "Searching")] if poe else [])
    runtime = make_runtime(tmp_path, lab)
    original = lab.port_config()
    req = ask(changes=changes)
    preview = execute.preview(runtime, "lab", req)
    assert preview["result"] == "ready", preview
    status = "untested" if poe or "allowed-vlans-all" in changes else "tested"
    assert preview["firmware_support"]["status"] == status
    assert [line.strip() for line in preview["commands"] if line.strip().startswith(("set ", "unset "))] == commands
    assert not lab.applied_blocks
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, "lab", req)
    assert refused.value.reason_codes == ["plan_changed"]
    result = execute.apply(runtime, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    readback = fortios.shown_switch_port(lab.port_config(), KEY)
    assert engine.observed_state(result["plan"], readback) == result["plan"]["predicted"]["after"]
    assert all(readback.get(name) == expected.get(name) for name in changes)
    undo = execute.preview_undo(runtime, result["change_id"], "Restore lab port", issue=True)
    assert undo["result"] == "ready", undo
    returned = execute.undo(runtime, result["change_id"], "Restore lab port", expected_plan_sha256=undo["plan_sha256"])
    assert returned["result"] == "confirmed", returned
    assert lab.port_fields == ManagedSwitch().port_fields
    assert engine.verify(result["plan"], lab.snapshot().encode(), expect="before")["result"] == "match"
    assert not lab.stitches and not lab.actions and not lab.triggers
    assert sorted(lab.port_config().splitlines()) == sorted(original.splitlines())


@pytest.mark.parametrize(("changes", "protected", "code"), [
    ({"vlan": "absent"}, {}, "fortiswitch_vlan_invalid"),
    ({"allowed-vlans": ["host02"]}, {}, "fortiswitch_vlan_invalid"),
    ({"allowed-vlans-all": "enable"}, {"interface": ["host01"]}, "port_management_vlan"),
    ({"vlan": "host02"}, {"interface": ["host02"]}, "port_management_vlan"),
    ({"vlan": "host02"}, {"system interface": ["host02"]}, "port_management_vlan"),
    ({"vlan": "host02"}, {"interface": ["port5"]}, "port_protected"),
    ({"poe-status": "disable"}, {}, "poe_not_capable"),
])
def test_invalid_vlan_protection_and_no_poe_refuse_before_write(tmp_path, changes, protected, code):
    lab = ManagedSwitch()
    plan = execute.preview(make_runtime(tmp_path, lab, protected=protected), "lab", ask(changes=changes))
    assert plan["result"] == "rejected" and plan["reason_codes"] == [code], plan
    assert not lab.applied_blocks


@pytest.mark.parametrize("answer", [POWERED.rsplit("Current", 1)[0], POWERED.replace("Port(5)", "Port(4)"),
                                    "Command fail. Return code -61"])
def test_incomplete_or_refused_poe_observation_is_not_a_capability_answer(tmp_path, answer):
    lab = ManagedSwitch([answer])
    result = execute.preview(make_runtime(tmp_path, lab), "lab", ask(changes={"poe-status": "disable"}))
    assert result["reason_codes"] == ["state_unreadable"]
    assert not lab.applied_blocks


def test_poe_read_timeout_is_distinguished_from_device_refusal(tmp_path):
    lab = ManagedSwitch([TimeoutError()])
    result = execute.preview(make_runtime(tmp_path, lab), "lab", ask(changes={"poe-status": "disable"}))
    assert result["reason_codes"] == ["fortiswitch_read_timeout"]
    assert not lab.applied_blocks


def test_active_vlan_preview_binds_explicit_endpoint_impact(tmp_path):
    lab = ManagedSwitch()
    runtime = make_runtime(tmp_path, lab)
    key = SERIAL + ":port4"
    changes = {"allowed-vlans": ["quarantine", "host02"]}
    result = execute.preview(runtime, "lab", ask(key=key, changes=changes))
    assert result["reason_codes"] == ["endpoint_impact_required"]
    # Model an endpoint using the G17 capture's live LLDP column layout.
    lab.lldp_override = lab.check_query(f"{exec_fortios.SWITCH_INFO} lldp neighbors-summary {SERIAL}").replace("BRWS", "S   ")
    result = execute.preview(runtime, "lab", ask(key=key, changes=changes, endpoint_impact=key))
    assert result["result"] == "ready", result
    assert any(f"Explicit endpoint impact accepted for {key}" in check for check in result["prechecks"])
    assert not lab.applied_blocks


@pytest.mark.parametrize(("answer", "code"), [
    (None, "poe_not_capable"),
    (POWERED.replace("Delivering Power", "Searching"), "poe_device_not_powered"),
    (POWERED, "endpoint_impact_required"),
])
def test_poe_cycle_checks_capability_and_impact_even_when_link_is_down(tmp_path, monkeypatch, answer, code):
    lab = ManagedSwitch([answer] if answer is not None else [])
    runtime = make_runtime(tmp_path, lab)
    monkeypatch.setattr(mcp_server, "configured_runtime", lambda: runtime)
    args = arguments(table=fortios.SWITCH_POE_CYCLE, key=KEY, op="update", changes={"poe-status": "disable"})
    assert call("admin_preview", args)["reason_codes"] == [code]
    assert not lab.applied_blocks


@pytest.mark.parametrize("observe_reset", [True, False])
def test_poe_cycle_requires_hash_and_proof_through_mcp(tmp_path, monkeypatch, observe_reset):
    lab = ManagedSwitch([POWERED], reset_readback=POWER_OFF if observe_reset else None)
    start = lab.clock
    runtime = make_runtime(tmp_path, lab)
    runtime.monotonic = lambda: (lab.clock - start).total_seconds()
    monkeypatch.setattr(mcp_server, "configured_runtime", lambda: runtime)
    args = arguments(table=fortios.SWITCH_POE_CYCLE, key=KEY, op="update", changes={"poe-status": "disable"},
                     endpoint_impact=KEY)
    preview = call("admin_preview", args)
    assert preview["result"] == "ready", preview
    assert preview["firmware_support"]["status"] == "untested"
    assert preview["commands"] == [POE_RESET]
    assert preview["predicted"]["before"] == preview["predicted"]["after"]
    assert not lab.applied_blocks
    assert call("admin_apply", args)["reason_codes"] == ["plan_changed"]
    result = call("admin_apply", {**args, "expected_plan_sha256": preview["plan_sha256"]})
    assert lab.resets == 1
    assert result["result"] == ("confirmed" if observe_reset else "reverted"), result
    if observe_reset:
        assert result["readback"]["down"] == {"poe": "Searching", "watts": "0.00", "current_ma": 0}
    assert result["readback"]["after"] == {"poe": "Delivering Power", "watts": "6.40", "current_ma": 120}
    assert lab.port_config() == ManagedSwitch().port_config()
    assert not lab.stitches and not lab.actions and not lab.triggers
    with pytest.raises(Rejected) as refused:
        execute.preview_undo(runtime, result["change_id"], "Try undo")
    assert refused.value.reason_codes == ["undo_not_applicable"]


def test_verify_legacy_plan_with_existing_vlans():
    lab = ManagedSwitch()
    plan = engine.build_plan("fortios", lab.snapshot().encode(), ask(changes={"description": "old schema"}))
    plan.pop("state_schema")
    for state in plan["predicted"].values():
        for field in fortios.SWITCH_VLAN_FIELDS:
            state.pop(field, None)
    snapshot = fortios.load(lab.snapshot(), None)
    plan["rest_sha256"] = snapshot.rest_digest(fortios.SWITCH_PORT, KEY)
    plan["plan_sha256"] = engine.plan_digest(plan)
    assert engine.verify(plan, lab.snapshot().encode(), expect="before")["result"] == "match"
    lab.port_fields["vlan"] = ["host02"]
    assert engine.verify(plan, lab.snapshot().encode(), expect="before")["result"] == "mismatch"


def test_poe_cycle_does_not_confirm_when_status_changes_without_power_loss(tmp_path, monkeypatch):
    lab = ManagedSwitch([POWERED], reset_readback=POWERED.replace("Delivering Power", "Searching"))
    start = lab.clock
    runtime = make_runtime(tmp_path, lab)
    runtime.monotonic = lambda: (lab.clock - start).total_seconds()
    monkeypatch.setattr(mcp_server, "configured_runtime", lambda: runtime)
    args = arguments(table=fortios.SWITCH_POE_CYCLE, key=KEY, op="update", changes={"poe-status": "disable"},
                     endpoint_impact=KEY)
    preview = call("admin_preview", args)
    assert preview["result"] == "ready", preview
    result = call("admin_apply", {**args, "expected_plan_sha256": preview["plan_sha256"]})
    assert lab.resets == 1
    assert result["result"] == "reverted", result
    assert "down" not in result["readback"]
    assert lab.port_config() == ManagedSwitch().port_config()
    assert not (lab.stitches or lab.actions or lab.triggers)


def test_repeated_current_value_does_not_make_verified_vlan_change_untested(tmp_path):
    """G17/G18: firmware_support follows the fields that change the port, not the ones that only repeat it."""
    previews = []
    for changes in ({"vlan": "host02"}, {"vlan": "host02", "allowed-vlans-all": "disable"}):
        runtime = make_runtime(tmp_path, ManagedSwitch())
        previews.append(execute.preview(runtime, "lab", ask(changes=changes)))
    for preview in previews:
        assert preview["result"] == "ready", preview
        assert preview["firmware_support"]["status"] == "tested", preview["firmware_support"]
    set_lines = [[line.strip() for line in p["commands"] if line.strip().startswith(("set ", "unset "))]
                 for p in previews]
    assert set_lines[0] == set_lines[1] == ['set vlan "host02"']
