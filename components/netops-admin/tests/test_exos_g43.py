"""1.0.12 G43 (X14, XP14): ExtremeXOS VLAN rename and a VLAN plan with its ports.

Fixtures in fixtures/exos_g43 are real answers of X440-G2-12p-10G4 33.7.1.6-patch1-11 (G43 lab measurement on a
test VLAN g43m/g43n tag 3943 and test port 10), anonymised with tests/support/anonymize_fixture.py:
x440__config-vlan-*.out are the vlan module of show configuration after "create vlan g43m tag 3943", description
and "add ports 10 tagged" (tagged), after "configure vlan g43m name g43n" (renamed), after moving port 10 untagged
(untagged) and after "delete vlan g43n" (deleted: port 10 has no native VLAN); x440__show-vlan-*.out are
show vlan <name> of the same states, show vlan of an absent name, show vlan Default and LAB, and show vlan.
The fake transport below only keeps the state; every answer it gives is one of these measured texts with the
names, tags and port rows of its state put in the measured places.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import request_bytes
from enrollment_helpers import certify
from fake_exos import FakeExos
from test_execute_exos import make_runtime

from netops_admin import engine, execute, exos
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIXTURES = Path(__file__).parent / "fixtures" / "exos_g43"
FIRMWARE = "33.7.1.6"
TAIL = "#\n# Module upm configuration.\n#\n"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def config(name: str) -> bytes:
    return (fixture("x440__config-vlan-%s.out" % name) + TAIL).encode("utf-8")


def base() -> bytes:
    """The state before the measurement: the tagged state without the test VLAN (the measurement returned to it,
    show configuration hash before = after)."""
    text = fixture("x440__config-vlan-tagged.out")
    text = "".join(line for line in text.splitlines(keepends=True) if "g43m" not in line)
    return (text + TAIL).encode("utf-8")


def req(op="create", key="g43n", changes=None, request_id="g43-0001"):
    if changes is None:
        changes = {"tag": 3943, "description": "g43 test"}
    return parse_request(request_bytes(table="vlan", op=op, key=key, changes=changes, request_id=request_id))


def plan(snapshot: bytes, request, **options):
    return engine.build_plan("exos", snapshot, request, firmware=FIRMWARE, device="sw", **options)


# --- check account parser on measured show vlan answers ------------------------------------------------------------

@pytest.mark.parametrize("name, expected", [
    ("tagged", {"tagged-ports": "10"}),
    ("renamed", {"tagged-ports": "10"}),
    ("untagged", {"untagged-ports": "10"}),
    ("lab", {"tagged-ports": "1"}),
    ("default", {"untagged-ports": " ".join(sorted(str(port) for port in range(1, 17)))}),
])
def test_measured_vlan_port_blocks_are_read(name, expected):
    assert exos.shown_vlan_ports(fixture("x440__show-vlan-%s.out" % name)) == expected


def test_a_cut_off_port_block_is_refused():
    text = fixture("x440__show-vlan-default.out")
    cut = text.split("                  15b,    16b")[0]
    with pytest.raises(Rejected) as caught:
        exos.shown_vlan_ports(cut)
    assert "lists 14 VLAN ports, not 16" in caught.value.reasons[0]
    with pytest.raises(Rejected):
        exos.shown_vlan_ports(text.replace("    Ports:   16.", "    Ports:"))
    with pytest.raises(Rejected):
        exos.shown_vlan_ports(text.replace("*3,", "*3?,"))


# --- X14 rename: plan, verify and refusals on measured snapshots ----------------------------------------------------

def rename(new="g43n", key="g43m", snapshot=None, **options):
    return plan(snapshot or config("tagged"), req("update", key, {"name": new}), **options)


def test_rename_plan_keeps_tag_description_and_ports():
    document = rename()
    assert document["commands"] == ["configure vlan g43m name g43n"]
    assert document["inverse"] == ["configure vlan g43n name g43m"]
    assert document["predicted"] == {"before": {"tag": "3943", "description": "g43 test", "name": "g43m"},
                                     "after": {"tag": "3943", "description": "g43 test", "name": "g43n"}}
    # measured: after the rename every reference (here the port membership) carries the new name
    assert engine.verify(document, config("renamed"), "after")["result"] == "match"
    assert engine.verify(document, config("tagged"), "before")["result"] == "match"
    assert engine.verify(document, config("tagged"), "after")["result"] == "mismatch"
    assert engine.verify(document, config("renamed"), "before")["result"] == "mismatch"


def test_a_reference_left_on_the_old_name_is_a_difference():
    document = rename()
    text = config("renamed").decode().replace("configure vlan g43n add ports 10 tagged",
                                              "configure vlan g43m add ports 10 tagged")
    verdict = engine.verify(document, text.encode(), "after")
    assert verdict["result"] == "mismatch" and not verdict["rest_matches"]


def test_a_left_over_old_vlan_is_a_difference():
    document = rename()
    text = config("renamed").decode().replace('create vlan "g43n"', 'create vlan "g43n"\ncreate vlan "g43m"')
    verdict = engine.verify(document, text.encode(), "after")
    assert "VLAN g43m still exists" in verdict["differences"]


@pytest.mark.parametrize("new, reason", [
    ("LAB", "already used"),
    ("G43M", "only in letter case"),
    ("Mgmt", "protected or reserved"),
    ("netops-enroll-x", "protected or reserved"),
])
def test_rename_refusals(new, reason):
    with pytest.raises(Rejected) as caught:
        rename(new)
    assert any(reason in text for text in caught.value.reasons)


def test_rename_is_alone_and_only_an_update():
    with pytest.raises(Rejected) as caught:
        plan(config("tagged"), req("update", "g43m", {"name": "g43n", "description": "x"}))
    assert caught.value.reasons == ["a VLAN rename is a separate request: it changes only the name"]
    with pytest.raises(Rejected) as caught:
        plan(base(), req("create", "g43n", {"tag": 3943, "name": "x"}))
    assert "takes no name attribute" in caught.value.reasons[0]


def test_rename_refuses_a_vlan_named_in_a_upm_script():
    text = config("tagged").decode().replace(
        TAIL, TAIL + "create upm profile watch\nconfigure vlan g43m add ports 11 tagged\n.\n")
    with pytest.raises(Rejected) as caught:
        rename(snapshot=text.encode())
    assert any("UPM script" in reason for reason in caught.value.reasons)


def test_protected_vlan_is_not_renamed():
    with pytest.raises(Rejected) as caught:
        rename(protected={"vlan": ["g43m"]})
    assert caught.value.reasons == ["object 'g43m' is protected"]


# --- XP14 a VLAN with its ports in one plan --------------------------------------------------------------------------

def test_create_with_an_untagged_port_matches_the_measured_state_and_returns_to_default():
    document = plan(base(), req(changes={"tag": 3943, "description": "g43 test", "untagged-ports": ["10"]}))
    assert document["commands"] == ["create vlan g43n tag 3943", 'configure vlan g43n description "g43 test"',
                                    "configure vlan g43n add ports 10 untagged"]
    assert document["inverse"] == ["configure vlan Default add ports 10 untagged", "delete vlan g43n"]
    assert document["predicted"]["after"] == {"tag": "3943", "description": "g43 test", "untagged-ports": "10"}
    assert engine.verify(document, config("untagged"), "after")["result"] == "match"
    assert engine.verify(document, base(), "before")["result"] == "match"
    # measured: delete vlan alone leaves port 10 without a native VLAN; that is not the state before
    verdict = engine.verify(document, config("deleted"), "before")
    assert verdict["result"] == "mismatch"
    assert "port 10: expected untagged in Default, found none" in verdict["differences"]


def test_create_with_tagged_ports_matches_the_measured_state():
    document = plan(base(), req(changes={"tag": 3943, "description": "g43 test", "tagged-ports": ["10"]}))
    assert document["commands"][-1] == "configure vlan g43n add ports 10 tagged"
    assert document["inverse"] == ["delete vlan g43n"]
    assert engine.verify(document, config("renamed"), "after")["result"] == "match"


def test_several_ports_are_one_plan_with_one_inverse():
    document = plan(base(), req(changes={"tag": 3943, "tagged-ports": ["2", "3", "4"], "untagged-ports": ["10", "11"]}))
    assert document["commands"] == ["create vlan g43n tag 3943", "configure vlan g43n add ports 2,3,4 tagged",
                                    "configure vlan g43n add ports 10,11 untagged"]
    assert document["inverse"] == ["configure vlan Default add ports 10,11 untagged", "delete vlan g43n"]


def test_update_adds_and_removes_ports_together():
    document = plan(config("untagged"), req("update", "g43n", {"tagged-ports": ["2", "3"], "untagged-ports": []}))
    assert document["predicted"]["before"] == {"tag": "3943", "description": "g43 test", "untagged-ports": "10"}
    assert document["predicted"]["after"] == {"tag": "3943", "description": "g43 test", "tagged-ports": "2 3"}
    assert document["commands"] == ["configure vlan Default add ports 10 untagged",
                                    "configure vlan g43n add ports 2,3 tagged"]
    assert document["inverse"] == ["configure vlan g43n delete ports 2,3", "configure vlan g43n add ports 10 untagged"]


def test_delete_of_a_vlan_with_ports_needs_its_ports_named():
    with pytest.raises(Rejected) as caught:
        plan(config("untagged"), req("delete", "g43n", {}))
    assert caught.value.reasons == ["object 'g43n' is referenced in the configuration"]
    with pytest.raises(Rejected) as caught:
        plan(config("untagged"), req("delete", "g43n", {"untagged-ports": ["11"]}))
    assert "exactly the current ports" in caught.value.reasons[0]
    document = plan(config("untagged"), req("delete", "g43n", {"untagged-ports": ["10"]}))
    assert document["commands"] == ["configure vlan Default add ports 10 untagged", "delete vlan g43n"]
    assert document["inverse"] == ["create vlan g43n tag 3943", 'configure vlan g43n description "g43 test"',
                                   "configure vlan g43n add ports 10 untagged"]
    assert engine.verify(document, base(), "after")["result"] == "match"
    assert engine.verify(document, config("deleted"), "after")["result"] == "mismatch"


def test_grouped_preview_refuses_a_port_protected_by_the_audit_policy(tmp_path):
    target = G43Exos()
    runtime = make_runtime(tmp_path, target)
    device = runtime.config.devices["sw"]
    policy = {"version": 1, "platform": "exos", "protected_ports": ["10"],
              "management_vlans": [], "port_vlans": {}}
    runtime.config = replace(runtime.config, devices={"sw": replace(device, audit_policy=policy)})
    certify(runtime, target, "sw")
    preview = execute.preview(runtime, "sw", req(changes={"tag": 3943, "untagged-ports": ["10"]}))
    assert preview["result"] == "rejected"
    assert preview["reasons"] == ["the requested object is protected by the audit policy"]
    assert not target.applied_blocks


def test_delete_refuses_membership_command_in_upm_profile():
    snapshot = config("untagged")
    body = req("delete", "g43n", {"untagged-ports": ["10"]})
    with pytest.raises(Rejected, match="referenced in the configuration"):
        plan(snapshot + b"create upm profile watch\nconfigure vlan g43n add ports 11 tagged\n.\n", body)


def test_grouped_verify_detects_a_membership_command_in_upm_profile():
    prefix = b"create upm profile watch\n"
    command = b"configure vlan g43n add ports 11 tagged\n"
    snapshot = config("untagged") + prefix + command + b".\n"
    document = plan(snapshot, req("update", "g43n", {"tagged-ports": ["2"]}))
    assert engine.verify(document, snapshot, expect="before")["result"] == "match"
    changed = snapshot.replace(command, command.replace(b"11", b"12"))
    verdict = engine.verify(document, changed, expect="before")
    assert verdict["object_matches"] and not verdict["rest_matches"]


@pytest.mark.parametrize("op", ["create", "delete"])
def test_explicit_empty_vlan_port_lists_verify_on_the_original_snapshot(op):
    snapshot = base()
    changes = {"tagged-ports": [], "untagged-ports": []}
    if op == "create":
        changes["tag"] = 3943
    else:
        snapshot = config("renamed").replace(b"configure vlan g43n add ports 10 tagged", b"")
    document = plan(snapshot, req(op, changes=changes))
    verdict = engine.verify(document, snapshot, expect="before")
    assert verdict["result"] == "match", verdict["differences"]


@pytest.mark.parametrize("changes, protected, reason", [
    ({"tag": 3943, "tagged-ports": ["10"], "untagged-ports": ["10"]}, None, "tagged and untagged"),
    ({"tag": 3943, "untagged-ports": ["10"]}, {"ports": ["10"]}, "protected"),
    ({"tag": 3943, "tagged-ports": ["1:2-3"]}, None, "port number"),
    ({"tag": 3943, "tagged-ports": ["0"]}, None, "port number"),
])
def test_port_plan_refusals(changes, protected, reason):
    with pytest.raises(Rejected) as caught:
        plan(base(), req(changes=changes), protected=protected)
    assert any(reason in text for text in caught.value.reasons), caught.value.reasons


def test_an_untagged_port_outside_default_is_refused():
    with pytest.raises(Rejected) as caught:
        plan(config("untagged"), req(key="g43x", changes={"tag": 3944, "untagged-ports": ["10"]}))
    assert "untagged port 10 is not an untagged member of Default" in caught.value.reasons[0]


def test_a_link_aggregation_port_is_refused():
    text = base().decode().replace(TAIL, "enable sharing 5 grouping 5-6 algorithm address-based L3_L4 lacp\n" + TAIL)
    with pytest.raises(Rejected) as caught:
        plan(text.encode(), req(changes={"tag": 3943, "tagged-ports": ["6"]}))
    assert "link aggregation" in caught.value.reasons[0]


def test_the_predicted_configuration_moves_the_port():
    from netops_admin import prediction
    document = plan(base(), req(changes={"tag": 3943, "description": "g43 test", "untagged-ports": ["10"]}))
    predicted = exos.load(prediction.snapshot_after(base().decode(), document), FIRMWARE)
    assert exos.vlan_ports(predicted, "g43n") == {"untagged-ports": "10"}
    assert exos.natives(predicted)["10"] == {"g43n"}
    renamed = rename()
    predicted = exos.load(prediction.snapshot_after(config("tagged").decode(), renamed), FIRMWARE)
    assert exos.vlan_ports(predicted, "g43n") == {"tagged-ports": "10"} and predicted._entry("g43m") is None


# --- the whole Admin run through a fake transport with measured answers -------------------------------------------

def _ranges(ports) -> str:
    numbers = sorted(int(port) for port in ports)
    parts, start = [], None
    for index, number in enumerate(numbers):
        if start is None:
            start = number
        if index + 1 == len(numbers) or numbers[index + 1] != number + 1:
            parts.append(str(start) if start == number else "%d-%d" % (start, number))
            start = None
    return ",".join(parts)


class G43Exos(FakeExos):
    """FakeExos with port membership and rename as measured (auto-move from Default, delete leaves no native)."""

    def __init__(self):
        super().__init__()
        self.vlans.pop("DATA")
        self.native = {str(port): "Default" for port in range(1, 17)}
        self.tagged = {str(port): set() for port in range(1, 17)}
        self.ignore = None
        self.truncate_check = False

    def _command(self, words, automatic):
        if words[:2] == ["configure", "vlan"] and len(words) == 5 and words[3] == "name":
            old, new = words[2], words[4]
            if old not in self.vlans or new in self.vlans:
                return False
            self.vlans = {new if name == old else name: value for name, value in self.vlans.items()}
            self.native = {port: new if vlan == old else vlan for port, vlan in self.native.items()}
            for names in self.tagged.values():
                if old in names:
                    names.discard(old)
                    names.add(new)
        elif words[:2] == ["configure", "vlan"] and len(words) in (6, 7) and words[3] in ("add", "delete") \
                and words[4] == "ports":
            name, ports = words[2], words[5].split(",")
            if name not in self.vlans or any(port not in self.native for port in ports):
                return False
            if self.ignore is not None and self.ignore in words and not automatic:
                return True
            for port in ports:
                if words[3] == "delete":
                    self.tagged[port].discard(name)
                    if self.native[port] == name:
                        self.native[port] = None
                elif words[6] == "untagged":
                    self.native[port] = name  # measured auto-move
                else:
                    self.tagged[port].add(name)
        elif words[:2] == ["delete", "vlan"] and len(words) == 3 and words[2] in self.vlans:
            self.vlans.pop(words[2])
            self.native = {port: None if vlan == words[2] else vlan for port, vlan in self.native.items()}
            for names in self.tagged.values():
                names.discard(words[2])
        else:
            return super()._command(words, automatic)
        self.unsaved = True
        return True

    def snapshot(self):
        text = super().snapshot()
        lines = ["configure vlan default delete ports all", "configure vr VR-Default delete ports 1-16",
                 "configure vr VR-Default add ports 1-16"]
        head, rest = text.split("# Module vlan configuration.\n#\n", 1)
        members = []
        for name in self.vlans:
            untagged = [port for port, vlan in self.native.items() if vlan == name]
            tagged = [port for port, names in self.tagged.items() if name in names]
            members += ["configure vlan %s add ports %s untagged  " % (name, _ranges(untagged))] if untagged else []
            members += ["configure vlan %s add ports %s tagged  " % (name, _ranges(tagged))] if tagged else []
        vlan_lines, after = rest.split("#\n# Module ems", 1)
        return (head + "# Module vlan configuration.\n#\n" + "\n".join(lines) + "\n" + vlan_lines
                + "\n".join(members) + "\n#\n# Module ems" + after)

    def check_query(self, command):
        words = command.split()
        if words[:2] != ["show", "vlan"]:
            return super().check_query(command)
        if len(words) == 2:
            lines = fixture("x440__show-vlan.out").splitlines(keepends=True)
            separators = [index for index, line in enumerate(lines) if set(line.strip()) == {"-"}]
            rows = ["%-15s %-4s -----------------------------------------------   ANY    0 /0   VR-Default \n"
                    % (name, value["tag"]) for name, value in self.vlans.items()]
            tail = [line for line in lines[separators[2]:] if not line.startswith("Total number of VLAN")]
            return "".join(lines[:separators[1] + 1] + rows + tail) + "Total number of VLAN(s) : %d \n" % len(self.vlans)
        name = words[2]
        if name not in self.vlans:
            return fixture("x440__show-vlan-absent.out").replace("g43m", name)
        value = self.vlans[name]
        text = fixture("x440__show-vlan-tagged.out")
        text = text.replace("with name g43m", "with name %s" % name).replace("Tag 3943", "Tag %s" % value["tag"])
        text = text.replace("Description:\t g43 test", "Description:\t %s" % value.get("description", "None"))
        untagged = [port for port, vlan in self.native.items() if vlan == name]
        tagged = [port for port, names in self.tagged.items() if name in names]
        block = "    Ports:   %d. \t  (Number of active ports=0)\n" % (len(untagged) + len(tagged))
        block += "       Untag:      %s\n" % ",     ".join(sorted(untagged, key=int)) if untagged else ""
        block += "       Tag:        %s\n" % ",     ".join(sorted(tagged, key=int)) if tagged else ""
        if self.truncate_check and (untagged or tagged):
            block = block.rsplit(",", 1)[0] + "\n" if "," in block else block.replace(block.splitlines()[-1] + "\n", "")
        return re.sub(r"    Ports:.*?(?=\tFlags:)", lambda _match: block, text, count=1, flags=re.S)


def apply(runtime, request, **options):
    preview = execute.preview(runtime, "sw", request)
    assert preview["result"] == "ready", preview
    return preview, execute.apply(runtime, "sw", request, expected_plan_sha256=preview["plan_sha256"], **options)


# Live check 2026-11-17 (task 469-r4, task-evidence/g43/r4/reserved-live.json): EXOS-VM 33.6.1.14 and X440-G2
# 33.7.1.6 both accept these Table 7 words as VLAN names, so they are not reserved; both reject ipv6 and management.
ACCEPTED_BY_BOTH_SWITCHES = {"bvlan", "cvlan", "ipagent", "ipv4", "isid", "l2vpn", "license-info", "mac-binding",
                             "mpls", "node", "ospvdebug", "svlan"}


def test_reserved_vlan_names_follow_live_switch_check():
    assert not ACCEPTED_BY_BOTH_SWITCHES & exos.RESERVED_VLAN_NAMES
    assert {"ipv6", "management", "security", "system", "log", "time", "web", "rmon"} <= exos.RESERVED_VLAN_NAMES
    assert len(exos.RESERVED_VLAN_NAMES) == 245
    # Pins the whole set (469-r4-rv): swapping two names outside the lists above changes the digest.
    # Digest of the 245 names that either switch rejected in reserved-live.json, sorted, newline-joined.
    assert hashlib.sha256("\n".join(sorted(exos.RESERVED_VLAN_NAMES)).encode()).hexdigest() == (
        "e84b759e3847ed88fea99c08209f6b3c0d73116937163103e259038ecdd8f1f7")
    for name in ("ipv4", "node", "mpls"):
        exos.validate_vlan_name(name)
    with pytest.raises(Rejected):
        exos.validate_vlan_name("Management")


@pytest.mark.parametrize("op", ["create", "update"], ids=["create", "rename"])
@pytest.mark.parametrize("name, expected", [
    ("ipv6", "rejected"),
    ("IPv6", "rejected"),
    ("VLAN", "rejected"),
    ("management", "rejected"),
    ("IPv4", "ready"),
    ("node", "ready"),
    ("g43n", "ready"),
    ("vlan2", "ready"),
])
def test_preview_checks_reserved_vlan_names(tmp_path, op, name, expected):
    device = G43Exos()
    if op == "update":
        device.vlans["g43m"] = {"tag": "3943", "description": "g43 test"}
        request = req("update", "g43m", {"name": name})
    else:
        request = req("create", name)
    runtime = make_runtime(tmp_path, device)

    preview = execute.preview(runtime, "sw", request)

    assert preview["result"] == expected, preview
    if expected == "rejected":
        assert preview["reason_codes"] == ["vlan_name_reserved"]
        assert preview["reasons"] == [f"VLAN name {name!r} is a reserved ExtremeXOS keyword"]
        assert "commands" not in preview


def test_create_with_ports_preview_apply_readback_and_undo(tmp_path):
    device = G43Exos()
    runtime = make_runtime(tmp_path, device)
    before = device.snapshot()
    request = req(changes={"tag": 3943, "description": "g43 test", "tagged-ports": ["2", "3"], "untagged-ports": ["10"]})
    preview = execute.preview(runtime, "sw", request)
    assert preview["result"] == "ready" and device.applied_blocks == [] and not device.unsaved
    assert preview["commands"] == ["create vlan g43n tag 3943", 'configure vlan g43n description "g43 test"',
                                   "configure vlan g43n add ports 2,3 tagged", "configure vlan g43n add ports 10 untagged"]
    assert "ports 2,3,10 are reported by the switch" in preview["prechecks"]
    record = execute.apply(runtime, "sw", request, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert device.native["10"] == "g43n" and device.tagged["2"] == {"g43n"} and device.tagged["3"] == {"g43n"}
    assert "check_identity_passed" in [step["step"] for step in record["steps"]] and device.saves == 1
    # the readback of the check account is the measured show vlan answer of the new VLAN
    assert exos.shown_vlan_ports(device.check_query("show vlan g43n")) == {"tagged-ports": "2 3", "untagged-ports": "10"}
    undo_preview = execute.preview_undo(runtime, record["change_id"], "G43 return")
    assert undo_preview["result"] == "ready"
    assert undo_preview["commands"] == ["configure vlan Default add ports 10 untagged", "delete vlan g43n"]
    undone = execute.undo(runtime, record["change_id"], "G43 return")
    assert undone["result"] == "confirmed", undone
    assert "g43n" not in device.vlans and device.native["10"] == "Default"
    assert device.snapshot() == before and not device.profiles and not device.timers


def test_rename_preview_apply_readback_and_undo(tmp_path):
    device = G43Exos()
    device.vlans["g43m"] = {"tag": "3943", "description": "g43 test"}
    device.tagged["10"].add("g43m")
    runtime = make_runtime(tmp_path, device)
    before = device.snapshot()
    preview, record = apply(runtime, req("update", "g43m", {"name": "g43n"}))
    assert preview["commands"] == ["configure vlan g43m name g43n"]
    assert record["result"] == "confirmed", record
    assert "g43n" in device.vlans and "g43m" not in device.vlans and device.tagged["10"] == {"g43n"}
    undone = execute.undo(runtime, record["change_id"], "G43 return")
    assert undone["result"] == "confirmed", undone
    assert device.snapshot() == before


def test_a_port_the_switch_did_not_move_is_compensated_by_the_safeguard(tmp_path):
    device = G43Exos()
    device.ignore = "untagged"
    runtime = make_runtime(tmp_path, device)
    before = device.snapshot()
    _preview, record = apply(runtime, req(changes={"tag": 3943, "tagged-ports": ["2"], "untagged-ports": ["10"]}))
    assert record["result"] == "reverted" and record["reason"] == "prediction mismatch"
    # the one compensating inverse removed the whole plan: the VLAN, its tagged port and Default for port 10
    assert device.snapshot() == before and not device.profiles and not device.timers


def test_a_port_unknown_to_the_switch_is_refused_before_any_write(tmp_path):
    device = G43Exos()
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "sw", req(changes={"tag": 3943, "tagged-ports": ["40"]}))
    assert preview["result"] == "rejected" and "port 40 is not reported by the switch" in preview["reasons"]
    assert device.applied_blocks == []


def test_an_incomplete_check_account_answer_is_refused_before_any_write(tmp_path):
    device = G43Exos()
    device.vlans["g43n"] = {"tag": "3943", "description": "g43 test"}
    device.native["10"] = "g43n"
    device.native["11"] = "g43n"
    device.truncate_check = True
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "sw", req("update", "g43n", {"untagged-ports": ["10"]}))
    assert preview["result"] == "rejected" and "check account" in preview["reasons"][0]
    assert device.applied_blocks == []
