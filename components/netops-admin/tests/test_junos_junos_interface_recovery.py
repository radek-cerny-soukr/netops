"""Junos profile batches through FastMCP and the Admin engine."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from fake_junos import fixture as cli_fixture
from netops_admin import cli, config, exec_junos, junos, mcp_server
from netops_admin.access import AccessError
from test_cli import run
from test_junos import NAME, make_runtime
from test_junos_junos_static_routing import FakeL3
from test_mcp_server import call

FIXTURES = Path(__file__).parent / "fixtures" / "junos_junos_interface_recovery"
PORT, VLAN, IRB = "ge-0/0/4", "NETOPS-PORT-3923", "irb.3923"
DESCRIBE = {"table": "interface", "op": "update", "key": PORT, "changes": {"description": "NETOPS-JUNOS-INTERFACE-RECOVERY"}}
CREATE_VLAN = {"table": "vlan", "op": "create", "key": "3923", "changes": {"name": VLAN}}
CREATE_IRB = {"table": "irb", "op": "create", "key": IRB,
              "changes": {"ipv4-address": "198.51.100.1/24", "vlan": VLAN}}


def captured(name):
    return (FIXTURES / name).read_text()


class BatchJunos(FakeL3):
    incomplete = False
    refuse_vlan = False
    absent_readback = False

    def __init__(self):
        super().__init__()
        self.sent_lines = []

    def _line(self, line, session):
        self.sent_lines.append(line)
        if line == junos.BATCH_BASELINE:
            return "\n".join(self._candidate(session))
        if line == junos.BATCH_COMPARE:
            return self._compare(self._candidate(session))
        if self.refuse_vlan and line == f"set vlans {VLAN} vlan-id 3923":
            return cli_fixture("set-bogus__syntax-error.txt")
        return super()._line(line, session)

    def query(self, command):
        if command == f"show interfaces {PORT} terse" and PORT not in self.up_ports:
            output = captured("port-terse.txt")
            return output.splitlines()[0] + "\n" if self.incomplete else output
        if command == f"show interfaces {IRB} terse" and self._irb_configured():
            return captured("port-terse.txt").splitlines()[0] + f"\n{IRB:<24}up    down inet\n"
        if command == "show vlans" and VLAN not in self.vlans():
            return captured("vlans.txt").rstrip() + "\n"
        return super().query(command)

    def _irb_configured(self):
        return any(line.startswith("set interfaces irb unit 3923 ") for line in self.lines)

    def check_query(self, command):
        if command == f"show interfaces {IRB} terse | display json | no-more":
            if not self._irb_configured() or self.absent_readback:
                return captured("irb-absent.json")
        if command == f"show vlans {VLAN} extensive | display json | no-more":
            return self._vlan_report(VLAN)
        return super().check_query(command)


def setup(tmp_path, monkeypatch, **kwargs):
    device = BatchJunos()
    runtime = make_runtime(tmp_path, device, **kwargs)
    runtime.config = replace(runtime.config, mcp_undo=True)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    monkeypatch.setattr(mcp_server, "_RUNTIME_FACTORY", lambda _: runtime)
    return device, runtime


def batch(*changes):
    return {"device": NAME, "table": "batch", "op": "update", "key": "batch", "changes": list(changes),
            "reason": "joint port VLAN and L3 change", "user_request": "approve this lab plan",
            "request_id": "junos-interface-recovery-mcp-001"}


def preview_and_apply(args):
    preview = call("admin_preview", args)
    assert preview["result"] == "ready", preview
    return call("admin_apply", {**args, "expected_plan_sha256": preview["plan_sha256"]})


def mutations(device):
    return [line for line in device.sent_lines if line.startswith(("set interfaces ", "set vlans ", "delete ", "commit"))]


def test_mcp_shared_candidate_preview_confirmation_and_undo(tmp_path, monkeypatch):
    device, _ = setup(tmp_path, monkeypatch)
    baseline = device.snapshot()
    args = batch(DESCRIBE, CREATE_VLAN, CREATE_IRB)
    preview = call("admin_preview", args)
    assert preview["result"] == "ready", preview
    assert preview["commands"].count(junos.BATCH_COMPARE) == 1
    assert not mutations(device)
    refused = call("admin_apply", args)
    assert refused["reason_codes"] == ["plan_changed"]
    assert not mutations(device)
    applied = call("admin_apply", {**args, "expected_plan_sha256": preview["plan_sha256"]})
    assert applied["result"] == "confirmed", applied
    assert [step["result"] for step in applied["operations"]] == ["verified"] * 3
    assert sum(line.startswith("commit confirmed ") for line in mutations(device)) == 1
    assert not device.pending()
    assert f"set vlans {VLAN} l3-interface {IRB}" in device.lines
    assert f"set interfaces {PORT} description NETOPS-JUNOS-INTERFACE-RECOVERY" in device.lines
    assert call("admin_status", {"request_id": args["request_id"]})["operations"] == applied["operations"]
    undo_args = {"change_id": applied["change_id"], "reason": "restore lab"}
    undo_preview = call("admin_undo_preview", undo_args)
    assert undo_preview["result"] == "ready", undo_preview
    restored = call("admin_undo", {**undo_args, "expected_plan_sha256": undo_preview["plan_sha256"]})
    assert restored["result"] == "confirmed", restored
    assert device.snapshot() == baseline
    assert not device.pending()
    assert sum(line.startswith("commit confirmed ") for line in mutations(device)) == 2


def test_second_edit_refusal_discards_the_first_edit(tmp_path, monkeypatch):
    device, _ = setup(tmp_path, monkeypatch)
    baseline, history = device.snapshot(), list(device.history)
    device.refuse_vlan = True
    response = preview_and_apply(batch(DESCRIBE, CREATE_VLAN, CREATE_IRB))
    assert response["result"] == "reverted", response
    assert [(op["result"], op.get("rollback")) for op in response["operations"]] == [
        ("reverted", "candidate-discarded"), ("failed", "candidate-discarded"), ("not-run", None)]
    assert mutations(device)[:2] == [f'set interfaces {PORT} description "NETOPS-JUNOS-INTERFACE-RECOVERY"', f"set vlans {VLAN} vlan-id 3923"]
    assert not any(line.startswith("commit ") for line in mutations(device))
    assert (device.snapshot(), device.history) == (baseline, history)


def test_session_loss_before_second_edit_discards_only_the_sent_step(tmp_path, monkeypatch):
    device, _ = setup(tmp_path, monkeypatch)
    baseline, history = device.snapshot(), list(device.history)
    second_edit = f"set vlans {VLAN} vlan-id 3923"

    def disconnect(_device, line):
        if line == second_edit:
            raise AccessError("SSH session closed before sending the edit")

    device.before_line = disconnect
    response = preview_and_apply(batch(DESCRIBE, CREATE_VLAN, CREATE_IRB))
    assert response["result"] == "reverted", response
    assert second_edit not in mutations(device)
    assert (device.snapshot(), device.history) == (baseline, history)
    assert [(op["result"], op.get("rollback")) for op in response["operations"]] == [
        ("reverted", "candidate-discarded"), ("failed", None), ("not-run", None)]
    assert response["steps"].count("batch_step_start") == 1


def test_existing_trunk_changes_only_its_new_batch_member(tmp_path, monkeypatch):
    device, _ = setup(tmp_path, monkeypatch)
    baseline = device.snapshot()
    trunk = "ge-0/0/0"
    args = batch(CREATE_VLAN, {
        "table": "vlan-membership", "op": "update", "key": trunk, "endpoint_impact": trunk,
        "changes": {"trunk-vlans": ["D10", "D20", VLAN]},
    })
    applied = preview_and_apply(args)
    assert applied["result"] == "confirmed", applied
    undo_args = {"change_id": applied["change_id"], "reason": "restore lab trunk"}
    preview = call("admin_undo_preview", undo_args)
    assert preview["result"] == "ready", preview
    restored = call("admin_undo", {**undo_args, "expected_plan_sha256": preview["plan_sha256"]})
    assert restored["result"] == "confirmed", restored
    path = f"interfaces {trunk} unit 0 family ethernet-switching vlan members {VLAN}"
    assert [line for line in mutations(device) if "vlan members" in line] == ["set " + path, "delete " + path]
    assert device.snapshot() == baseline and not device.pending()


@pytest.mark.parametrize("problem, expected", [("incomplete", "port_usage_unreadable"),
                                               ("active", "endpoint_impact_required"),
                                               ("protected", "port_protected")])
def test_preflight_refuses_before_any_mutation(tmp_path, monkeypatch, problem, expected):
    device, _ = setup(tmp_path, monkeypatch, protected={"interface": [PORT + ".0"]} if problem == "protected" else {})
    if problem == "incomplete":
        device.incomplete = True
    if problem == "active":
        device.up_ports.add(PORT)
    change = {**DESCRIBE, "changes": {"mtu": 9000}} if problem == "active" else DESCRIBE
    response = call("admin_preview", batch(CREATE_VLAN, change))
    assert response["reason_codes"] == [expected], response
    assert not mutations(device)


def test_loss_of_one_postcheck_returns_the_whole_activated_candidate(tmp_path, monkeypatch):
    device, _ = setup(tmp_path, monkeypatch)
    baseline = device.snapshot()

    def lose_irb_readback(fake, line):
        if line.startswith("commit confirmed "):
            fake.absent_readback = True

    device.after_line = lose_irb_readback
    response = preview_and_apply(batch(DESCRIBE, CREATE_VLAN, CREATE_IRB))
    assert response["result"] == "reverted", response
    assert "check_identity_failed" in response["steps"]
    assert any(line.endswith('-revert"') for line in mutations(device))
    assert device.snapshot() == baseline
    assert not device.pending()


def test_exclusive_candidate_is_rechecked_after_preview_and_before_activation(tmp_path, monkeypatch):
    device, _ = setup(tmp_path, monkeypatch)
    args = batch(DESCRIBE, CREATE_VLAN)
    preview = call("admin_preview", args)
    assert preview["result"] == "ready", preview

    def concurrent_change(fake, line):
        if line == junos.BATCH_BASELINE:
            fake.lines.append("set interfaces ge-0/0/8 description changed-elsewhere")

    device.before_line = concurrent_change
    response = call("admin_apply", {**args, "expected_plan_sha256": preview["plan_sha256"]})
    assert response["reason_codes"] == ["plan_changed"], response
    assert not mutations(device)
    assert not exec_junos.leftovers(device)


def test_cli_undo_accepts_the_approved_batch_preview(tmp_path, monkeypatch, capsys):
    device, runtime = setup(tmp_path, monkeypatch)
    baseline = device.snapshot()
    monkeypatch.setattr(config, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "build_runtime", lambda _config: runtime)
    arguments = ("--config", str(tmp_path / "admin.json"))
    request = tmp_path / "batch.json"
    request.write_text(json.dumps(batch(DESCRIBE, CREATE_VLAN)))
    target = (*arguments, "--device", NAME, "--request", str(request))
    code, preview = run(capsys, "preview", *target)
    assert (code, preview["result"]) == (0, "ready")
    code, applied = run(capsys, "apply", *target, "--expect-plan-sha256", preview["plan_sha256"])
    assert (code, applied["result"]) == (0, "confirmed")
    undo = (*arguments, "--change-id", applied["change_id"], "--reason", "restore test objects")
    code, undo_preview = run(capsys, "undo", *undo, "--preview")
    assert (code, undo_preview["result"]) == (0, "ready")
    code, restored = run(capsys, "undo", *undo, "--expect-plan-sha256", undo_preview["plan_sha256"])
    assert (code, restored["result"]) == (0, "confirmed")
    assert device.snapshot() == baseline and not device.pending()


def test_batch_rename_preview_projects_igmp_configuration(tmp_path, monkeypatch):
    device, _ = setup(tmp_path, monkeypatch)
    # Measured JUNOS-VLAN-ADMIN VLAN and IGMP CLI grammar with the test VLAN name.
    device.lines.append("set protocols igmp-snooping vlan D10 immediate-leave")
    project = junos.snapshot_after
    snapshots = []

    def capture(text, plan):
        projected = project(text, plan)
        snapshots.append(projected)
        return projected

    monkeypatch.setattr(junos, "snapshot_after", capture)
    result = call("admin_preview", batch({
        "table": "vlan", "op": "update", "key": "10", "changes": {"name": "junos-vlan-admin-renamed"},
    }, DESCRIBE))
    assert result["result"] == "ready", result
    assert snapshots and "set protocols igmp-snooping vlan junos-vlan-admin-renamed immediate-leave" in snapshots[-1].splitlines()
    assert "set protocols igmp-snooping vlan D10 immediate-leave" not in snapshots[-1].splitlines()


@pytest.mark.parametrize("lldp", [False, True])
def test_membership_preview_shows_lldp_observation_with_consent(tmp_path, monkeypatch, lldp):
    device, _ = setup(tmp_path, monkeypatch)
    port = "ge-0/0/2"
    device.lldp_extra = [port] if lldp else []
    result = call("admin_preview", batch(CREATE_VLAN, {
        "table": "vlan-membership", "op": "update", "key": port, "endpoint_impact": port,
        "changes": {"access-vlan": VLAN},
    }))
    assert result["result"] == "ready", result
    assert any("LLDP neighbor: " + ("present" if lldp else "absent") in row
               for row in result["operations"][1]["prechecks"])


def test_batch_preview_accepts_description_on_active_port_without_endpoint_impact(tmp_path, monkeypatch):
    device, _ = setup(tmp_path, monkeypatch)
    device.up_ports.add(PORT)
    result = call("admin_preview", batch(CREATE_VLAN, DESCRIBE))
    assert result["result"] == "ready", result
    assert not mutations(device)
