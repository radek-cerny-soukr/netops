"""1.0.12 G131 (EP14): ordered EOS profile batches under one commit timer.

The EOS adapter of the batch of G106 is exercised through the Admin engine with FakeEos, which builds every answer
from outputs measured on cEOSLab 4.36.1F (fixtures/eos_4_36_1F, eos_g122, eos_g123 and the lab outputs of
fixtures/eos_g131). A device refusal of one line reuses the measured answer text of fixtures/eos_g123."""
from __future__ import annotations

from pathlib import Path

import pytest
from fake_eos import FakeEos, g123_answer
from test_eos import make_runtime, request, steps

from netops_admin import eos, execute
from netops_admin.errors import Rejected
from netops_admin.engine import verify

DEVICE = "lab-ceos"
VLAN = "3931"
FIXTURES = Path(__file__).parent / "fixtures" / "eos_g131"
CREATE_VLAN = {"table": "vlan", "op": "create", "key": VLAN, "changes": {"name": "NETOPS-G131"}}
MOVE_PORT = {"table": "vlan-membership", "op": "update", "key": "Ethernet12", "changes": {"access-vlan": int(VLAN)},
             "endpoint_impact": "Ethernet12"}
DESCRIBE = {"table": "interface", "op": "update", "key": "Ethernet13", "changes": {"description": "NETOPS-G131"},
            "endpoint_impact": "Ethernet13"}


def captured(lab, name):
    return (FIXTURES / f"{lab}-{name}.txt").read_text()


class BatchEos(FakeEos):
    def __init__(self):
        super().__init__()
        self.refuse = None

    def _line(self, line, mode):
        if line == self.refuse and mode[0] != "exec":
            return g123_answer("interface-line-mtu-9215__max.txt")
        return super()._line(line, mode)


def batch(*operations, **fields):
    return request(table="batch", key="batch", changes=list(operations), request_id="g131-batch", **fields)


@pytest.fixture
def lab(tmp_path):
    device = BatchEos()
    return device, make_runtime(tmp_path, device)


@pytest.mark.parametrize("lab_name, port", (("d-ceos", "Ethernet12"), ("b04-eos-a", "Ethernet5"),
                                            ("b04-eos-b", "Ethernet5")))
def test_lab_outputs_identify_a_connected_access_port_and_a_missing_vlan(lab_name, port):
    status = eos.status_row(captured(lab_name, "status"), port)
    assert status == "connected"
    assert eos.membership(captured(lab_name, "switchport"), port)["access-vlan"] == "1"
    assert eos.description_row(captured(lab_name, "description"), port)["description"] == ""
    assert eos.vlan_exists(captured(lab_name, "vlan-missing"), VLAN) is False


@pytest.mark.parametrize("third", (False, True))
def test_dependent_vlan_port_and_description_batch_applies_and_undoes(lab, third):
    device, runtime = lab
    before = list(device.lines)
    operations = [CREATE_VLAN, MOVE_PORT] + ([DESCRIBE] if third else [])
    req = batch(*operations)
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "ready", preview
    assert [step["table"] for step in preview["operations"]] == [step["table"] for step in operations]
    assert not device.applied_blocks
    with pytest.raises(Rejected) as denied:
        execute.apply(runtime, DEVICE, req)
    assert denied.value.reason_codes == ["plan_changed"]
    assert not device.applied_blocks

    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), steps(record))
    assert [step["result"] for step in record["batch_results"]] == ["verified"] * len(operations)
    assert verify(record["plan"], "\n".join(device.lines).encode())["result"] == "match"
    assert device.vlan_name(VLAN) == "NETOPS-G131" and "switchport access vlan " + VLAN in device.interface("Ethernet12")
    assert len(device.sessions) == 0 and device.timer is None

    undo_preview = execute.preview_undo(runtime, record["change_id"], "restore", issue=True)
    assert undo_preview["result"] == "ready", undo_preview
    assert [step["table"] for step in undo_preview["operations"]] == [step["table"] for step in reversed(operations)]
    returned = execute.undo(runtime, record["change_id"], "restore", expected_plan_sha256=undo_preview["plan_sha256"])
    assert returned["result"] == "confirmed", (returned.get("reason"), steps(returned))
    assert device.lines == before and device.sessions == {}


def test_refusal_of_the_second_step_returns_the_first_step(lab):
    device, runtime = lab
    before = list(device.lines)
    first = {**DESCRIBE, "key": "Ethernet14", "endpoint_impact": "Ethernet14", "changes": {"description": "NETOPS-G131-A"}}
    req = batch(first, DESCRIBE)
    preview = execute.preview(runtime, DEVICE, req)
    assert preview["result"] == "ready", preview
    device.refuse = "description NETOPS-G131"
    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", (record.get("reason"), steps(record))
    assert [step["result"] for step in record["batch_results"]] == ["reverted", "failed"]
    assert ["configure terminal", "interface Ethernet14", "no description", "end"] in device.applied_blocks
    assert device.lines == before and device.sessions == {}


def test_every_step_is_written_under_the_pending_timer_only(lab):
    device, runtime = lab
    req = batch(CREATE_VLAN, MOVE_PORT)
    preview = execute.preview(runtime, DEVICE, req)
    device.on_apply = lambda fake, lines: seen.append((lines[1:2], fake.timer is not None))
    seen = []
    record = execute.apply(runtime, DEVICE, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed"
    written = [item for item in seen if item[0] and item[0][0] in ("vlan " + VLAN, "interface Ethernet12")]
    assert len(written) == 2 and all(timer for _, timer in written)


def test_active_port_needs_endpoint_impact(lab):
    device, runtime = lab
    refused = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, {k: v for k, v in MOVE_PORT.items()
                                                                   if k != "endpoint_impact"}))
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["endpoint_impact_required"], refused
    assert not device.applied_blocks


def test_batch_impact_for_description_is_explained_by_mcp_tools(lab):
    import asyncio

    from netops_admin.mcp_server import mcp

    device, runtime = lab
    describe = {"table": "interface", "op": "update", "key": "Ethernet12", "changes": {"description": "test"}}
    refused = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, describe))
    assert refused["reason_codes"] == ["endpoint_impact_required"] and not device.applied_blocks

    tools = {tool.name: tool.description for tool in asyncio.run(mcp.list_tools())}
    for name in ("admin_preview", "admin_apply"):
        assert "every EOS batch step on an active port or SVI, including description changes" in tools[name]


def test_protected_interface_is_refused_for_every_interface_table(lab, tmp_path):
    device, _ = lab
    runtime = make_runtime(tmp_path / "p", device, protected={"interface": ["Ethernet12", "Vlan10", "Port-Channel5"]})
    for operation in (MOVE_PORT, {**MOVE_PORT, "table": "interface", "changes": {"description": "x"}}):
        result = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, operation))
        assert result["result"] == "rejected" and result["reason_codes"] == ["port_protected"], result
    result = execute.preview(runtime, DEVICE, batch(
        CREATE_VLAN, {"table": "l3-interface", "op": "update", "key": "Vlan10", "changes": {"description": "x"}}))
    assert result["reason_codes"] == ["port_protected"], result
    assert not device.applied_blocks


def test_incomplete_status_answer_refuses_the_preview(lab):
    device, runtime = lab
    original = device.query

    def cut(command):
        text = original(command)
        return text.split("\n")[0] + "\n" if command == "show interfaces Ethernet13 status" else text

    device.query = cut
    result = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, DESCRIBE))
    assert result["result"] == "rejected" and result["reason_codes"] == ["port_usage_unreadable"], result
    assert not device.applied_blocks


def test_routing_profile_and_repeated_object_are_not_batched(lab):
    device, runtime = lab
    twice = {**DESCRIBE, "changes": {"description": "other"}}
    repeated = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, DESCRIBE, twice))
    assert repeated["result"] == "rejected" and repeated["reason_codes"] == ["action_unsupported"], repeated
    routing = {"table": "ospf-process", "op": "create", "key": "131", "changes": {"router-id": "192.0.2.131"}}
    staged = execute.preview(runtime, DEVICE, batch(CREATE_VLAN, routing))
    assert staged["result"] == "rejected" and staged["reason_codes"] == ["action_unsupported"], staged
    assert not device.applied_blocks


def test_new_highest_vlan_is_predicted_after_the_last_vlan_block_like_on_the_device():
    from netops_admin.engine import build_plan
    excerpt = (FIXTURES / "d-ceos-running-config-excerpt.txt").read_text()
    plan = build_plan("eos", excerpt.encode(), request(table="vlan", op="create", key=VLAN,
                                                       changes={"name": "NETOPS-G131"}), firmware="4.36.1F")
    lines = eos.snapshot_after(excerpt, plan).split("\n")
    start = lines.index("vlan 304")
    assert lines[start:start + 7] == ["vlan 304", "   name B04-EXOS-DOWNSTREAM", "!", "vlan 3931",
                                      "   name NETOPS-G131", "!", "aaa authorization exec default local"]
