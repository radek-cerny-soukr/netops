"""G24: one preview, one approval and a stepwise apply with readback and verified return for related FortiOS
objects (address -> address group -> firewall policy), against replies measured on a FortiGate-60F, FortiOS 7.6.8."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from fake_020 import FortiOS767
from fake_fortios import DeviceRefused, quoted
from test_execute import make_runtime, request

from netops_admin import engine, execute, fortios
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_core.fortios import tokenize

FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_g24"
ADDRESS, GROUP, POLICY = "firewall address", "firewall addrgrp", "firewall policy"
HOST, GROUP_KEY, POLICY_ID = "NETOPS-G24-HOST", "NETOPS-G24-GROUP", "240024"
STEP_ADDRESS = {"table": ADDRESS, "op": "create", "key": HOST, "changes": {"subnet": "192.0.2.124/32", "comment": "G24 host"}}
STEP_GROUP = {"table": GROUP, "op": "create", "key": GROUP_KEY,
              "changes": {"member": [HOST], "comment": "G24 group"}}
POLICY_CHANGES = {"name": "NETOPS-G24-POLICY", "srcintf": ["netops-g14"], "dstintf": ["g14-lo"], "srcaddr": ["all"],
                  "dstaddr": [GROUP_KEY], "action": "accept", "schedule": "always", "service": ["ALL_TCP"],
                  "logtraffic": "all", "status": "disable"}
STEP_POLICY = {"table": POLICY, "op": "create", "key": POLICY_ID, "changes": POLICY_CHANGES}
STEPS = (STEP_ADDRESS, STEP_GROUP, STEP_POLICY)


def capture(name):
    return (FIXTURES / (name + ".txt")).read_text()


class Lab(FortiOS767):
    """Address, group and policy tables of a FortiOS 7.6.8 with the lab interfaces; the check account answers with the
    measured replies whenever its simulated object equals the measured one."""
    firmware = ("7.6.8", "3744")

    def __init__(self):
        super().__init__()
        self.groups.clear()
        self.interfaces += ["netops-g14", "g14-lo"]
        self.services["ALL_TCP"] = {}
        self.policies["8"] = {"name": "netops-g14-ping", "srcintf": "netops-g14", "dstintf": "g14-lo",
                              "srcaddr": "all", "dstaddr": "all", "service": "ALL_TCP", "action": "accept",
                              "schedule": "always", "status": "enable"}
        self.line_sent = None
        self.step_blocks = {}
        self.unsent_at = None
        self.lost_at = None
        self.timeout_check = False

    @staticmethod
    def _blocks(lines):
        blocks, current, depth = [], [], 0
        for line in lines:
            words = line.split()
            depth += words[:1] == ["config"]
            current.append(line)
            depth -= words[:1] == ["end"]
            if depth == 0:
                blocks.append(current)
                current = []
        return blocks + ([current] if current else [])

    def _run(self, lines, automatic=False):
        blocks = self._blocks(lines) if automatic else [lines]
        if len(blocks) > 1:
            # a safeguard script returns several tables in one run
            return sum(self._run(block, automatic) for block in blocks)
        if lines[0].strip() == "config firewall policy" and not automatic:
            current = None
            for number, line in enumerate(lines, 1):
                words = tokenize(line.strip())
                if words[:1] == ["edit"]:
                    current = words[1]
                if words[:2] == ["set", "name"] and any(
                        key != current and row.get("name") == words[2] for key, row in self.policies.items()):
                    # measured: policy-duplicate-name-refused.txt; the unfinished entry is never committed
                    raise DeviceRefused(number - 1)
        return super()._run(lines, automatic)

    def apply(self, lines, spec):
        first = lines[0].strip()
        if first.startswith("config firewall"):
            table = first.removeprefix("config ")
            count = self.step_blocks[table] = self.step_blocks.get(table, 0) + 1
            if (self.unsent_at, ) == ((table, count),):
                raise AccessError("the session could not be opened", 0)
            if self.line_sent is not None:
                self.line_sent()
            if (self.lost_at, ) == ((table, count),):
                super().apply(lines, spec)
                raise AccessError("interactive session failed after %d lines: connection lost" % len(lines), len(lines))
        return super().apply(lines, spec)

    def _measured(self, table, key, state, label):
        sample = fortios.parse_snapshot(capture(label)).section(table).entries[key]
        expected = {name: attr.value() if name != "member" else " ".join(quoted(v) for v in attr.values)
                    for name, attr in sample.attrs.items() if name != "uuid"}
        view = {name: value for name, value in state.items() if name != "uuid"}
        if table == POLICY:
            view = {name: value for name, value in view.items() if self.policy_hidden.get(name) != value}
            expected = {name: " ".join(tokenize(value)) for name, value in expected.items()}
            view = {name: " ".join(tokenize(value)) for name, value in view.items()}
        elif table == GROUP:
            expected["member"], view["member"] = (" ".join(sorted(tokenize(v["member"]))) for v in (expected, view))
        if expected == view:
            return capture(label).replace(sample.attrs["uuid"].value(), state["uuid"])
        return None

    def check_query(self, command):
        if self.timeout_check:
            raise TimeoutError("check read timed out")
        if command == f'show {ADDRESS} "{HOST}"' and HOST in self.addresses:
            return self._measured(ADDRESS, HOST, self.addresses[HOST], "address-created") or super().check_query(command)
        if command == f'show {GROUP} "{GROUP_KEY}"' and GROUP_KEY in self.groups:
            state = {**self.groups[GROUP_KEY], "uuid": self.groups[GROUP_KEY].setdefault("uuid", self._uuid())}
            return self._measured(GROUP, GROUP_KEY, state, "group-created") or super().check_query(command)
        if command == f"show {POLICY} {POLICY_ID}" and POLICY_ID in self.policies:
            return self._measured(POLICY, POLICY_ID, self.policies[POLICY_ID], "policy-created") or super().check_query(command)
        if command.startswith(("show firewall address ", "show firewall addrgrp ", "show firewall policy ")) and (
                command.split('"')[1] if '"' in command else command.split()[-1]) not in {
                **self.addresses, **self.groups, **self.policies}:
            return capture("absent")
        return super().check_query(command)


def runtime(tmp_path, device, **fields):
    fields.setdefault("opt_in", (POLICY,))
    fields.setdefault("protected", {"system interface": ["wan1"]})
    return make_runtime(tmp_path, device, **fields)


def batch(*steps, **fields):
    fields.setdefault("request_id", "g24-batch-0001")
    return request(table="batch", key="batch", op="update", changes=[copy.deepcopy(step) for step in steps], **fields)


def written(device):
    return [block for block in device.applied_blocks if block[0].startswith("config firewall")]


def why(record):
    return json.dumps([[step["step"], step.get("detail")] for step in record["steps"]]
                      + [[item["index"], item["result"], item.get("failure"), item.get("rollback")]
                         for item in record["batch_results"]] + [record.get("reason")], default=str)


def results(record):
    return [step["result"] for step in record["batch_results"]]


def events(record, name):
    return [step["detail"] for step in record["steps"] if step["step"] == name]


def approved(rt, device, req):
    before, writes = device.snapshot(), len(device.applied_blocks)
    preview = execute.preview(rt, "lab", req)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == before and len(device.applied_blocks) == writes
    return preview


def state(device):
    return (copy.deepcopy(device.addresses), copy.deepcopy(device.groups), copy.deepcopy(device.policies))


def test_one_preview_one_hash_stepwise_apply_readback_and_undo(tmp_path):
    device = Lab()
    rt = runtime(tmp_path, device)
    before = device.snapshot()
    req = batch(*STEPS)
    preview = approved(rt, device, req)
    assert [step["table"] for step in preview["operations"]] == [ADDRESS, GROUP, POLICY]
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", why(record)
    assert results(record) == ["verified"] * 3
    assert events(record, "batch_step_start") == ["1", "2", "3"]
    assert events(record, "batch_step_verified") == ["1", "2", "3"]
    assert [block[0] for block in written(device)] == ["config firewall address", "config firewall addrgrp",
                                                       "config firewall policy"]
    assert device.addresses[HOST]["subnet"] == "192.0.2.124 255.255.255.255"
    assert device.groups[GROUP_KEY]["member"] == HOST and device.policies[POLICY_ID]["dstaddr"] == GROUP_KEY
    assert device.policies[POLICY_ID]["status"] == "disable" and list(device.policies)[-1] == POLICY_ID
    assert not device.stitches and not device.triggers and not device.actions
    # the check account reads back exactly what was measured on the FortiGate
    assert device.check_query(f'show {ADDRESS} "{HOST}"') == capture("address-created").replace(
        "00000000-0000-4000-8000-0000000000a1", device.addresses[HOST]["uuid"])
    assert engine.verify(record["plan"], device.snapshot().encode())["result"] == "match"
    undo_preview = execute.preview_undo(rt, record["change_id"], "return the G24 objects", issue=True)
    assert undo_preview["result"] == "ready", undo_preview
    assert [step["table"] for step in undo_preview["operations"]] == [POLICY, GROUP, ADDRESS]
    undone = execute.undo(rt, record["change_id"], "return the G24 objects", undo_preview["plan_sha256"])
    if undone["result"] != "confirmed":
        diag = [(st["table"], engine.verify(dict(st, safeguard_id=None), device.snapshot().encode(), "before")["differences"])
                for st in undone["plan"]["batch_steps"][:1]]
        raise AssertionError((why(undone), diag, undone["plan"]["batch_steps"][0].get("batch_volatile")))
    assert results(undone) == ["verified"] * 3
    assert [block[1].strip() for block in written(device)[-3:]] == [f'delete "{POLICY_ID}"', f'delete "{GROUP_KEY}"',
                                                                    f'delete "{HOST}"']
    assert device.snapshot().replace("\n", "") == before.replace("\n", "")
    assert not device.stitches and not device.triggers and not device.actions


def test_new_address_joins_an_existing_group_in_one_batch_and_undo_restores_the_members(tmp_path):
    device = Lab()
    device.groups["NETOPS-G24-OLD"] = {"member": "srv-web spare-host", "comment": "existing"}
    rt = runtime(tmp_path, device)
    before = device.snapshot()
    steps = (STEP_ADDRESS, {"table": GROUP, "op": "update", "key": "NETOPS-G24-OLD",
                            "changes": {"member": ["srv-web", "spare-host", HOST]}})
    req = batch(*steps)
    preview = approved(rt, device, req)
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", why(record)
    assert set(device.groups["NETOPS-G24-OLD"]["member"].split()) == {"srv-web", "spare-host", HOST}
    undo_preview = execute.preview_undo(rt, record["change_id"], "return", issue=True)
    assert undo_preview["result"] == "ready", undo_preview
    undone = execute.undo(rt, record["change_id"], "return", undo_preview["plan_sha256"])
    assert undone["result"] == "confirmed", why(undone)
    assert set(device.groups["NETOPS-G24-OLD"]["member"].split()) == {"srv-web", "spare-host"}
    assert HOST not in device.addresses
    # the members are the original ones; their order is the one Admin writes (sorted), not the one the device had
    assert device.snapshot().count("srv-web") == before.count("srv-web")


@pytest.mark.parametrize("manual_uuid", (True, False))
def test_delete_batch_returns_the_objects_with_their_attributes(tmp_path, manual_uuid):
    from netops_admin.config import DEFAULT_LIMITS

    device = Lab()
    device.manual_policy_uuid = manual_uuid
    # each step of a batch counts against the hourly budget of the device (6 by default): create, delete and undo need 9
    rt = runtime(tmp_path, device, limits={**DEFAULT_LIMITS, "changes_per_device_per_hour": 12})
    created = execute.apply(rt, "lab", batch(*STEPS, request_id="g24-create-0001"),
                            expected_plan_sha256=execute.preview(rt, "lab", batch(*STEPS, request_id="g24-create-0001"))["plan_sha256"])
    assert created["result"] == "confirmed", why(created)
    before = device.snapshot()
    gone = (dict(STEP_POLICY, op="delete", changes={}), dict(STEP_GROUP, op="delete", changes={}),
            dict(STEP_ADDRESS, op="delete", changes={}))
    req = batch(*gone, request_id="g24-delete-0001")
    preview = approved(rt, device, req)
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", why(record)
    assert POLICY_ID not in device.policies and GROUP_KEY not in device.groups and HOST not in device.addresses
    undo_preview = execute.preview_undo(rt, record["change_id"], "return", issue=True)
    assert undo_preview["result"] == "ready", undo_preview
    undone = execute.undo(rt, record["change_id"], "return", undo_preview["plan_sha256"])
    assert undone["result"] == "confirmed", why(undone)
    assert device.addresses[HOST]["subnet"] == "192.0.2.124 255.255.255.255" and device.groups[GROUP_KEY]["member"] == HOST
    assert device.policies[POLICY_ID]["dstaddr"] == GROUP_KEY and device.policies[POLICY_ID]["status"] == "disable"
    assert list(device.policies)[-1] == POLICY_ID
    # a device that does not let a user set the UUID gives the recreated policy a new one, and the record says so
    assert bool(undone.get("warnings")) is (not manual_uuid), undone.get("warnings")
    del before


def test_apply_without_the_approved_hash_is_refused_before_any_write(tmp_path):
    device = Lab()
    rt = runtime(tmp_path, device)
    req = batch(*STEPS)
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab", req)
    assert caught.value.reason_codes == ["plan_changed"]
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab", req, expected_plan_sha256="0" * 64)
    assert caught.value.reason_codes == ["plan_changed"]
    assert not device.applied_blocks and not device.stitches


def test_changed_order_or_content_invalidates_the_approval(tmp_path):
    device = Lab()
    rt = runtime(tmp_path, device)
    preview = approved(rt, device, batch(*STEPS))
    other = copy.deepcopy(STEP_ADDRESS)
    other["changes"]["comment"] = "another host"
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab", batch(other, STEP_GROUP, STEP_POLICY), expected_plan_sha256=preview["plan_sha256"])
    assert caught.value.reason_codes == ["plan_changed"]
    assert not device.applied_blocks


def test_policy_refused_by_the_device_returns_the_group_and_the_address_in_reverse_order(tmp_path):
    device = Lab()
    rt = runtime(tmp_path, device)
    before = device.snapshot()
    changes = {**POLICY_CHANGES, "name": "netops-g14-ping"}
    req = batch(STEP_ADDRESS, STEP_GROUP, {**STEP_POLICY, "changes": changes})
    preview = approved(rt, device, req)
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", why(record)
    assert results(record) == ["reverted", "reverted", "failed"]
    assert [step["rollback"] for step in record["batch_results"][:2]] == ["verified", "verified"]
    assert events(record, "batch_step_start") == ["1", "2", "3"]
    # the refused step is checked too: the object it was to create is absent, so it needs no inverse
    assert events(record, "batch_step_reverted") == ["3", "2", "1"]
    assert [block[1].strip() for block in written(device)[-2:]] == [f'delete "{GROUP_KEY}"', f'delete "{HOST}"']
    assert not any(block[1].strip().startswith("delete") and POLICY_ID in block[1] for block in written(device))
    assert device.snapshot() == before
    assert not device.stitches and not device.triggers and not device.actions
    assert capture("policy-duplicate-name-refused").splitlines()[-1] == "Command fail. Return code -651"


def test_step_the_session_never_sent_is_not_started_and_not_returned(tmp_path):
    device = Lab()
    device.unsent_at = (GROUP, 1)
    rt = runtime(tmp_path, device)
    before = device.snapshot()
    req = batch(*STEPS)
    preview = approved(rt, device, req)
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", why(record)
    assert results(record) == ["reverted", "failed", "not-run"]
    assert events(record, "batch_step_start") == ["1"]
    assert events(record, "batch_step_failed") == ["2"]
    assert events(record, "batch_step_reverted") == ["1"]
    assert "rollback" not in record["batch_results"][1]
    assert not any(block[1].strip() == f'delete "{GROUP_KEY}"' for block in written(device))
    assert device.snapshot() == before and not device.stitches


def test_step_sent_but_not_answered_is_started_and_returned(tmp_path):
    device = Lab()
    device.lost_at = (GROUP, 1)
    rt = runtime(tmp_path, device)
    before = device.snapshot()
    req = batch(*STEPS)
    preview = approved(rt, device, req)
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", why(record)
    assert results(record) == ["reverted", "failed", "not-run"]
    assert events(record, "batch_step_start") == ["1", "2"]
    assert events(record, "batch_step_reverted") == ["2", "1"]
    assert [block[1].strip() for block in written(device)[-2:]] == [f'delete "{GROUP_KEY}"', f'delete "{HOST}"']
    assert device.snapshot() == before and not device.stitches


def test_a_foreign_change_between_steps_stops_the_batch_and_leaves_the_return_to_the_safeguard(tmp_path):
    device = Lab()
    rt = runtime(tmp_path, device)
    before = device.snapshot()
    req = batch(*STEPS)
    preview = approved(rt, device, req)

    def foreign(fake, lines):
        if lines[0] == "config firewall addrgrp":
            fake.addresses["foreign-host"] = {"uuid": fake._uuid(), "subnet": "192.0.2.77 255.255.255.255"}

    device.on_apply = foreign
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    # the rest of the configuration no longer matches: Admin writes no inverse, the safeguard of the device returns
    # exactly the objects of the batch and leaves the foreign one; the result stays unknown (firing is not proven)
    assert record["result"] == "unknown", why(record)
    assert results(record) == ["verified", "failed", "not-run"]
    assert events(record, "batch_step_reverted") == []
    assert [block[0] for block in written(device)] == ["config firewall address", "config firewall addrgrp"]
    assert device.fired == set(device.stitches) and len(device.stitches) == 1
    assert HOST not in device.addresses and GROUP_KEY not in device.groups and POLICY_ID not in device.policies
    assert "foreign-host" in device.addresses and "foreign-host" not in before


@pytest.mark.parametrize("steps,reason", (
    ((STEP_ADDRESS, {"table": "firewall service custom", "op": "create", "key": "NETOPS-G24-SVC",
                     "changes": {"tcp-portrange": "8024"}}), "FortiOS batch holds"),
    ((STEP_ADDRESS, STEP_ADDRESS), "repeats"),
    ((STEP_GROUP, STEP_POLICY, {**STEP_POLICY, "key": "240026"}), "at most one firewall policy"),
    ((STEP_ADDRESS, {"table": POLICY, "op": "update", "key": "8", "changes": {"comments": "x"}}, STEP_POLICY),
     "at most one firewall policy"),
))
def test_batch_outside_the_measured_set_is_refused_with_its_code(tmp_path, steps, reason):
    device = Lab()
    rt = runtime(tmp_path, device, opt_in=(POLICY, "firewall service custom"))
    preview = execute.preview(rt, "lab", batch(*steps))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["action_unsupported"], preview
    assert reason in " ".join(preview["reasons"])
    assert not device.applied_blocks


def test_firmware_with_the_webhook_safeguard_is_refused_for_a_batch(tmp_path):
    device = Lab()
    device.firmware = ("8.0.2", "0251")
    rt = runtime(tmp_path, device)
    preview = execute.preview(rt, "lab", batch(*STEPS))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["action_unsupported"], preview
    assert "cli-script safeguard" in " ".join(preview["reasons"])
    assert not device.applied_blocks


def test_untested_firmware_is_a_warning_not_a_refusal(tmp_path):
    device = Lab()
    device.firmware = ("7.6.7", "3704")
    rt = runtime(tmp_path, device)
    preview = execute.preview(rt, "lab", batch(*STEPS))
    assert preview["result"] == "ready", preview
    assert preview["firmware_support"]["status"] == "untested"


def test_active_policy_needs_endpoint_impact_and_the_planner_accepts_it(tmp_path):
    device = Lab()
    rt = runtime(tmp_path, device)
    active = {**STEP_POLICY, "changes": {**POLICY_CHANGES, "status": "enable"}}
    preview = execute.preview(rt, "lab", batch(STEP_ADDRESS, STEP_GROUP, active))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_policy_impact_required"], preview
    with_impact = {**active, "endpoint_impact": POLICY_ID}
    req = batch(STEP_ADDRESS, STEP_GROUP, with_impact)
    preview = approved(rt, device, req)
    assert preview["operations"][2]["endpoint_impact"] == POLICY_ID
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", why(record)
    assert device.policies[POLICY_ID]["status"] == "enable"


def test_protected_interface_and_unknown_object_are_refused_in_the_preview(tmp_path):
    device = Lab()
    rt = runtime(tmp_path, device)
    wan = {**STEP_POLICY, "changes": {**POLICY_CHANGES, "srcintf": ["wan1"]}}
    preview = execute.preview(rt, "lab", batch(STEP_ADDRESS, STEP_GROUP, wan))
    assert preview["result"] == "rejected" and "protected object 'wan1'" in " ".join(preview["reasons"]), preview
    unknown = {**STEP_POLICY, "changes": {**POLICY_CHANGES, "dstaddr": ["NETOPS-G24-NOPE"]}}
    preview = execute.preview(rt, "lab", batch(STEP_ADDRESS, STEP_GROUP, unknown))
    assert preview["result"] == "rejected" and "missing from the visible snapshot" in " ".join(preview["reasons"]), preview
    assert not device.applied_blocks


def test_the_group_may_not_name_an_address_the_batch_does_not_create(tmp_path):
    device = Lab()
    rt = runtime(tmp_path, device)
    bad = {**STEP_GROUP, "changes": {"member": ["NETOPS-G24-NOPE"]}}
    preview = execute.preview(rt, "lab", batch(STEP_ADDRESS, bad, STEP_POLICY))
    assert preview["result"] == "rejected", preview
    assert not device.applied_blocks


def test_unreadable_check_account_before_any_write_has_its_own_reason_codes(tmp_path):
    for fault, code in ((RuntimeError("check account unavailable"), "fortios_batch_read_unreadable"),
                        (AccessError("read timed out after 30 s"), "fortios_batch_read_timeout")):
        device = Lab()
        rt = runtime(tmp_path / code, device)

        def broken(command, fault=fault):
            raise fault

        device.check_query = broken
        preview = execute.preview(rt, "lab", batch(*STEPS))
        assert preview["result"] == "rejected", preview
        assert preview["reason_codes"] == [code], preview
        assert not device.applied_blocks


def test_process_lost_between_steps_is_recovered_by_the_safeguard_of_the_device(tmp_path, monkeypatch):
    class ProcessLost(BaseException):
        pass

    device = Lab()
    rt = runtime(tmp_path, device)
    before = device.snapshot()
    req = batch(*STEPS)
    preview = approved(rt, device, req)
    step = execute._step

    def lose(runtime_, record, name, detail=None):
        step(runtime_, record, name, detail)
        if name == "batch_step_verified" and detail == "2":
            raise ProcessLost()

    monkeypatch.setattr(execute, "_step", lose)
    with pytest.raises(ProcessLost):
        execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    monkeypatch.setattr(execute, "_step", step)
    assert HOST in device.addresses and GROUP_KEY in device.groups and POLICY_ID not in device.policies
    recovered, = execute.recover(rt, "lab")
    assert recovered["result"] == "reverted", why(recovered)
    assert device.snapshot() == before
    assert execute.recover(rt, "lab") == []


def test_command_limit_counts_each_step_and_the_safeguard_script_limit_all_steps(tmp_path, monkeypatch):
    from netops_admin.config import DEFAULT_LIMITS

    device = Lab()
    plan = engine.build_plan("fortios", device.snapshot().encode(), batch(*STEPS))
    longest = max(len(step["commands"]) for step in plan["batch_steps"])
    assert len(plan["commands"]) > longest
    ready = execute.preview(runtime(tmp_path / "each", device, limits={**DEFAULT_LIMITS, "plan_commands": longest}),
                            "lab", batch(*STEPS))
    assert ready["result"] == "ready", ready
    refused = execute.preview(runtime(tmp_path / "over", device, limits={**DEFAULT_LIMITS, "plan_commands": longest - 1}),
                              "lab", batch(*STEPS))
    assert refused["result"] == "rejected" and "more than %d commands" % (longest - 1) in " ".join(refused["reasons"])
    together = fortios.safeguard_script_length(plan["inverse"])
    assert max(fortios.safeguard_script_length(step["inverse"]) for step in plan["batch_steps"]) < together
    monkeypatch.setattr(fortios, "SAFEGUARD_SCRIPT_LIMIT", together - 1)
    refused = execute.preview(runtime(tmp_path / "script", device), "lab", batch(*STEPS))
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["safeguard_script_limit"], refused
    assert not device.applied_blocks


def test_rest_of_a_batch_step_ignores_the_volatile_ciphertext_and_the_order_of_member_values():
    # measured on the FortiGate-60F: the ciphertext of wireless-controller vap sae-password differs between two reads
    def text(cipher, members):
        return ("#config-version=FGT60F-7.6.8-FW-build3744-260420:opmode=1:vdom=0:user=x\n"
                "config wireless-controller vap\n    edit \"v\"\n        set sae-password ENC %s\n    next\nend\n"
                "config firewall addrgrp\n    edit \"g\"\n        set member %s\n    next\nend\n" % (cipher, members))

    one = fortios.load(text("AAAA", '"a" "b"'), None)
    two = fortios.load(text("BBBB", '"b" "a"'), None)
    assert one.rest_digest(ADDRESS, "x", batch=True) == two.rest_digest(ADDRESS, "x", batch=True)
    # outside a batch the order of the values still counts, the ciphertext never did
    assert one.rest_digest(ADDRESS, "x") != two.rest_digest(ADDRESS, "x")
    assert one.rest_digest(ADDRESS, "x") == fortios.load(text("CCCC", '"a" "b"'), None).rest_digest(ADDRESS, "x")


def test_preview_does_not_hold_or_print_secrets(tmp_path):
    device = Lab()
    rt = runtime(tmp_path, device)
    text = json.dumps(execute.preview(rt, "lab", batch(*STEPS)))
    assert "password" not in text.lower() and "ENC " not in text and "set password" not in text


def test_mcp_batch_preview_apply_status_and_undo(tmp_path, monkeypatch):
    from netops_admin import mcp_server
    from test_mcp_server import call

    device = Lab()
    rt = runtime(tmp_path, device)
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", rt.config)
    monkeypatch.setattr(mcp_server, "_RUNTIME_FACTORY", lambda _: rt)
    args = {"device": "lab", "table": "batch", "op": "update", "key": "batch", "reason": "related objects of one host",
            "user_request": "apply this approved plan", "request_id": "g24-mcp-0001", "changes": list(STEPS)}
    preview = call("admin_preview", args)
    assert preview["result"] == "ready" and not device.applied_blocks, preview
    refused = call("admin_apply", args)
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["plan_changed"] and not device.applied_blocks
    response = call("admin_apply", {**args, "expected_plan_sha256": preview["plan_sha256"]})
    assert response["result"] == "confirmed", response
    status = call("admin_status", {"request_id": args["request_id"]})
    assert status["operations"] == response["operations"]
    assert [step["result"] for step in status["operations"]] == ["verified"] * 3


# ---- the real Admin transport (OpenSSH client replaced by the fixture of the Fortinet SSH tests) ----

from test_fortinet_ssh_operation import count, wired  # noqa: E402,F401  (fixture)

HOSTS = ({"table": ADDRESS, "op": "create", "key": "netops-g24-a", "changes": {"subnet": "192.0.2.31/32"}},
         {"table": ADDRESS, "op": "create", "key": "netops-g24-b", "changes": {"subnet": "192.0.2.32/32"}})


@pytest.mark.parametrize("wired", ["fortios"], indirect=True)
def test_batch_over_the_real_ssh_session_starts_each_step_when_its_first_line_is_sent(wired):
    import pickle
    runtime, name, _, _, path = wired
    req = request(table="batch", key="batch", op="update", changes=[dict(step) for step in HOSTS],
                  request_id="g24-ssh-0001")
    preview = execute.preview(runtime, name, req)
    assert preview["result"] == "ready", preview
    count(wired, "batch preview")
    record = execute.apply(runtime, name, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", why(record)
    count(wired, "batch apply")
    assert events(record, "batch_step_start") == ["1", "2"] and results(record) == ["verified", "verified"]
    fake = pickle.loads((path / "device").read_bytes())
    assert {"netops-g24-a", "netops-g24-b"} <= set(fake.addresses) and not fake.stitches


def test_dialog_reports_the_send_only_after_the_line_was_written():
    import re
    import threading
    from unittest import mock

    from netops_admin import fortinet_cli
    from netops_core.session import SessionError

    def shell():
        fake = mock.MagicMock()
        fake._command_lock = threading.Lock()
        fake._limits = (1, 1, 10 ** 6, 10 ** 6)
        fake._prompt_pattern = re.compile(rb"\$ \Z")
        fake._platform = "fortios"
        fake._last_prompt = b""
        fake._expected_prompt.return_value = None
        fake._read_output.return_value = None
        return fake

    calls = []
    unsent = shell()
    unsent._write_input.side_effect = SessionError("the session is closed", code="closed")
    with pytest.raises(SessionError):
        fortinet_cli.dialog(unsent, "config firewall address", 5, sent=lambda: calls.append("sent"))
    assert calls == [] and unsent.close.called
    sent = shell()
    sent._write_input.side_effect = lambda *_: calls.append("written")
    fortinet_cli.dialog(sent, "config firewall address", 5, sent=lambda: calls.append("sent"))
    assert calls == ["written", "sent"]


@pytest.mark.parametrize("wired", ["fortios"], indirect=True)
def test_line_refused_inside_a_block_is_aborted_and_the_batch_returns_on_the_same_session(wired):
    import pickle
    runtime, name, _, _, path = wired
    req = request(table="batch", key="batch", op="update", changes=[dict(step) for step in HOSTS],
                  request_id="g24-ssh-0003")
    preview = execute.preview(runtime, name, req)
    assert preview["result"] == "ready", preview
    count(wired, "batch preview")
    # measured on the FortiGate-60F: a refused set inside edit leaves the CLI in that edit, `abort` leaves it
    (path / "refuse-line").write_text("192.0.2.32")
    record = execute.apply(runtime, name, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", why(record)
    assert results(record) == ["reverted", "failed"] and events(record, "batch_step_reverted") == ["2", "1"]
    # one held session of the write account and one of the check account for the whole operation
    count(wired, "batch refused line and return")
    fake = pickle.loads((path / "device").read_bytes())
    assert not ({"netops-g24-a", "netops-g24-b"} & set(fake.addresses)) and not fake.stitches


# ---- 1.0.12 G24 r2 (705-rv finding 1): a member change of a group changes the traffic of the policies that use it ----
USED_GROUP, OUTER_GROUP, USER_POLICY = "NETOPS-G24-USED", "NETOPS-G24-OUTER", "9"


def lab_with_group_in_policy(*, side="dstaddr", via_outer=False, status="enable"):
    device = Lab()
    device.groups[USED_GROUP] = {"member": "srv-web", "comment": "used"}
    names = USED_GROUP
    if via_outer:
        device.groups[OUTER_GROUP] = {"member": USED_GROUP, "comment": "outer"}
        names = OUTER_GROUP
    policy = {"name": "netops-g24-user", "srcintf": "netops-g14", "dstintf": "g14-lo", "srcaddr": "all",
              "dstaddr": "all", "service": "ALL_TCP", "action": "accept", "schedule": "always", "status": status}
    policy[side] = names
    device.policies[USER_POLICY] = policy
    return device


def add_member(**fields):
    return request(table=GROUP, op="update", key=USED_GROUP, changes={"member": ["srv-web", "spare-host"]},
                   request_id="g24-r2-group-0001", **fields)


def add_member_in_batch(**step):
    return batch(STEP_ADDRESS, {"table": GROUP, "op": "update", "key": USED_GROUP,
                                "changes": {"member": ["srv-web", HOST]}, **step}, request_id="g24-r2-batch-0001")


@pytest.mark.parametrize("side", ("dstaddr", "srcaddr"))
@pytest.mark.parametrize("via_outer", (False, True))
@pytest.mark.parametrize("shape", ("single", "batch"))
def test_group_used_by_a_protected_policy_is_not_changed_even_with_endpoint_impact(tmp_path, side, via_outer, shape):
    device = lab_with_group_in_policy(side=side, via_outer=via_outer)
    rt = runtime(tmp_path, device, protected={"system interface": ["wan1"], POLICY: [USER_POLICY]})
    before, writes = device.snapshot(), len(device.applied_blocks)
    for impact in (False, True):
        if shape == "single":
            req = add_member(**({"endpoint_impact": USED_GROUP} if impact else {}))
        else:
            req = add_member_in_batch(**({"endpoint_impact": USED_GROUP} if impact else {}))
        preview = execute.preview(rt, "lab", req)
        assert preview["result"] == "rejected", preview
        assert "protected firewall policy '%s'" % USER_POLICY in " ".join(preview["reasons"]), preview
        assert preview["reason_codes"] == execute.preview(rt, "lab", request(
            table=POLICY, op="update", key=USER_POLICY, changes={"comment": "x"}, request_id="g24-r2-direct-0001"
        ))["reason_codes"]
    assert device.snapshot() == before and len(device.applied_blocks) == writes


@pytest.mark.parametrize("shape", ("single", "batch"))
def test_group_used_by_an_active_policy_needs_endpoint_impact_and_the_planner_accepts_it(tmp_path, shape):
    device = lab_with_group_in_policy()
    rt = runtime(tmp_path, device)
    before = device.snapshot()
    without = add_member() if shape == "single" else add_member_in_batch()
    preview = execute.preview(rt, "lab", without)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_policy_impact_required"], preview
    assert device.snapshot() == before and not device.applied_blocks
    req = (add_member(endpoint_impact=USED_GROUP) if shape == "single"
           else add_member_in_batch(endpoint_impact=USED_GROUP))
    preview = approved(rt, device, req)
    operation = preview if shape == "single" else preview["operations"][1]
    assert any("Explicit endpoint impact accepted for address group" in item for item in operation["prechecks"]), operation
    if shape == "batch":
        assert operation["endpoint_impact"] == USED_GROUP
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", why(record)
    step_plan = record["plan"] if shape == "single" else record["plan"]["batch_steps"][1]
    assert step_plan["endpoint_impact"] == USED_GROUP
    assert set(device.groups[USED_GROUP]["member"].split()) == {"srv-web", "spare-host" if shape == "single" else HOST}
    undo_preview = execute.preview_undo(rt, record["change_id"], "return", issue=True)
    assert undo_preview["result"] == "ready", undo_preview
    undone = execute.undo(rt, record["change_id"], "return", undo_preview["plan_sha256"])
    assert undone["result"] == "confirmed", why(undone)
    assert device.groups[USED_GROUP]["member"] == "srv-web"


def test_active_policy_reached_through_a_parent_group_needs_endpoint_impact(tmp_path):
    device = lab_with_group_in_policy(via_outer=True)
    rt = runtime(tmp_path, device)
    assert execute.preview(rt, "lab", add_member())["reason_codes"] == ["fortios_policy_impact_required"]
    assert execute.preview(rt, "lab", add_member(endpoint_impact=USED_GROUP))["result"] == "ready"


@pytest.mark.parametrize("case", ("unused", "disabled-policy", "comment-only"))
def test_group_without_an_active_policy_or_member_change_is_planned_as_before(tmp_path, case):
    device = lab_with_group_in_policy(status="disable") if case == "disabled-policy" else Lab()
    if case != "disabled-policy":
        device.groups[USED_GROUP] = {"member": "srv-web", "comment": "used"}
    if case == "comment-only":
        device = lab_with_group_in_policy()
    rt = runtime(tmp_path, device, protected={"system interface": ["wan1"], POLICY: [USER_POLICY]}
                 if case != "disabled-policy" else {"system interface": ["wan1"]})
    changes = {"comment": "new comment"} if case == "comment-only" else {"member": ["srv-web", "spare-host"]}
    req = request(table=GROUP, op="update", key=USED_GROUP, changes=changes, request_id="g24-r2-plain-0001")
    preview = approved(rt, device, req)
    assert "endpoint_impact" not in preview
    # an impact nobody needs stays an unsupported request, as before
    unneeded = request(table=GROUP, op="update", key=USED_GROUP, changes=changes, endpoint_impact=USED_GROUP,
                       request_id="g24-r2-plain-0002")
    assert execute.preview(rt, "lab", unneeded)["result"] == "rejected"
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", why(record)
