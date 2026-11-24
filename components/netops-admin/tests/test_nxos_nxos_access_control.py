"""NXOS-ACCESS-CONTROL ACL preview, confirmed writes and inverse on measured NX-OS readbacks."""
from pathlib import Path
import re

import pytest

from fake_nxos import FakeNxos
from netops_admin import engine, exec_nxos, execute
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_nxos import make_runtime, request, steps

FIXTURES = Path(__file__).parent / "fixtures" / "nxos_nxos_access_control"
ACL, ATTACHMENT = "ip-access-list", "interface-access-group"
PORT = "Ethernet1/64"
SVI = "Vlan3910"
NAME4, NAME6 = "NETOPS-NXOS-ACCESS-CONTROL-V4", "NETOPS-NXOS-ACCESS-CONTROL-V6"
KEY4, KEY6 = "ipv4:" + NAME4, "ipv6:" + NAME6
RULES4 = "30 permit ip any any, 10 deny tcp host 192.0.2.64 any eq 443"
RULES6 = "30 permit ipv6 any any, 10 deny udp host 2001:db8:1::64 any eq 53"
CANONICAL4 = "10 deny tcp 192.0.2.64/32 any eq 443, 30 permit ip any any"
CANONICAL6 = "10 deny udp 2001:db8:1::64/128 any eq 53, 30 permit ipv6 any any"


def measured(name):
    return (FIXTURES / f"{name}.txt").read_text()


class ReplayAcl(FakeNxos):
    """Apply the orders sent by Admin and choose the recorded CLI observation for that state."""

    def __init__(self, target=PORT):
        super().__init__()
        self.target = target
        if target == SVI:
            self.body.extend(["interface Vlan3910", "  no shutdown"])
        self.saved = self._config()
        self.read_failure = None
        self.svi_up = False

    def _bindings(self):
        return [line for line in self.interface(self.target)
                if " access-group " in line or " traffic-filter " in line]

    def _config_line(self, words, mode):
        if words[:2] in (["ip", "access-list"], ["ipv6", "access-list"]):
            header = " ".join(words)
            if header not in self.body:
                self.body.append(header)
            mode[0] = "acl:" + header
            return ""
        if words[:3] in (["no", "ip", "access-list"], ["no", "ipv6", "access-list"]):
            start, end = self._block(" ".join(words[1:]))
            del self.body[start:end]
            return ""
        return super()._config_line(words, mode)

    def _line(self, line, mode):
        if not mode[0].startswith("acl:") or line == "end":
            return super()._line(line, mode)
        if line == "exit":
            mode[0] = "config"
            return ""
        start, end = self._block(mode[0][4:])
        entries = self.body[start + 1:end]
        if line.startswith("no "):
            number = int(line[3:])
            entries = [entry for entry in entries if int(entry.split()[0]) != number]
        else:
            entries.append("  " + line)
        self.body[start + 1:end] = sorted(entries, key=lambda entry: int(entry.split()[0]))
        return ""

    def _interface_line(self, name, words, line):
        binding = re.fullmatch(r"(no )?(ip(?: port)? access-group|ipv6(?: port)? traffic-filter) (\S+) (in|out)", line)
        if binding and name == self.target:
            drop = re.compile(rf"^{binding[2]} \S+ {binding[4]}$")
            self._set(name, drop, None if binding[1] else line)
            return ""
        return super()._interface_line(name, words, line)

    def query(self, command):
        scope = PORT if self.target == PORT else "vlan 3910"
        if command == "show interface vlan 3910":
            source = (FIXTURES.parent / "nxos_nxos_routing_admin" / "svi-up.txt").read_text().replace("Vlan20", SVI)
            return source if self.svi_up else source.replace("is up", "is down")
        if command == f"show running-config interface {scope}":
            self.queries.append(command)
            bindings = self._bindings()
            if not bindings:
                return measured("port_before" if self.target == PORT else "svi_before")
            family = "ipv6" if bindings[0].startswith("ipv6 ") else "ipv4"
            return measured(family + ("-pacl_interface" if self.target == PORT else "-svi_interface"))
        if command == f"show interface {PORT} status":
            return measured("port_status")
        if command == f"show mac address-table interface {PORT}":
            return measured("port_mac")
        if command == "show cdp neighbors":
            return measured("nexus9300v__cdp")
        return super().query(command)

    def check_query_status(self, command):
        if self.read_failure is not None:
            return self.read_failure(command)
        return 0, self.check_query(command)

    def check_query(self, command):
        parts = command.split()
        if parts[:3] in (["show", "ip", "access-lists"], ["show", "ipv6", "access-lists"]):
            self.check_queries.append(command)
            cli, name = parts[1], parts[3]
            family = "ipv4" if cli == "ip" else "ipv6"
            header = f"{cli} access-list {name}"
            summary = parts[-1] == "summary"
            if header not in self.body:
                return measured("nexus9300v__missing-summary" if summary else f"nexus9300v__acl{family[-1]}-missing")
            start, end = self._block(header)
            numbers = [int(line.split()[0]) for line in self.body[start + 1:end]]
            reordered = family + "-reordered"
            label = {(): "ipv6-empty", (10, 30): family + "-created", (20,): reordered}[tuple(numbers)]
            if summary and any(line.startswith(cli + " ") for line in self._bindings()):
                label = family + ("-pacl" if self.target == PORT else "-svi")
            text = measured(label + ("_summary" if summary else "_acl"))
            if summary:
                # Replay the captured attachment with the current number of ACEs.
                text = re.sub(r"Total ACEs Configured: \d+", f"Total ACEs Configured: {len(numbers)}", text)
            return text
        return super().check_query(command)


def req(table, key, changes, op="update", label="change"):
    return request(table=table, key=key, changes=changes, op=op, request_id="nxos-access-control-" + label)


def apply(runtime, fake, requested):
    before = fake._config()
    n = len(fake.applied_blocks)
    preview = execute.preview(runtime, "lab-nxos", requested)
    assert preview["result"] == "ready", preview
    assert fake._config() == before and len(fake.applied_blocks) == n
    record = execute.apply(runtime, "lab-nxos", requested, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert "check_identity_passed" in steps(record)
    assert fake.clean()
    return record


def undo(runtime, fake, record):
    reason = "verify exact NXOS-ACCESS-CONTROL undo"
    preview = execute.preview_undo(runtime, record["change_id"], reason, issue=True)
    assert preview["result"] == "ready", preview
    reverted = execute.undo(runtime, record["change_id"], reason, expected_plan_sha256=preview["plan_sha256"])
    assert reverted["result"] == "confirmed", reverted
    assert fake.clean()
    return reverted


@pytest.mark.parametrize("kind", ["create", "update", "bind"])
def test_wave6_acl_apply_always_requires_preview_hash(tmp_path, kind):
    fake = ReplayAcl()
    runtime = make_runtime(tmp_path, fake)
    if kind != "create":
        apply(runtime, fake, req(ACL, KEY4, {"rules": RULES4}, op="create", label="fixture"))
    change = {
        "create": req(ACL, KEY4, {"rules": RULES4}, op="create"),
        "update": req(ACL, KEY4, {"rules": "20 permit ip any any"}),
        "bind": req(ATTACHMENT, PORT + ":ipv4:in", {"acl": NAME4}),
    }[kind]
    before = len(fake.applied_blocks)
    assert execute.preview(runtime, "lab-nxos", change)["result"] == "ready"
    with pytest.raises(Rejected) as error:
        execute.apply(runtime, "lab-nxos", change)
    assert error.value.reason_codes == ["plan_changed"]
    assert len(fake.applied_blocks) == before


@pytest.mark.parametrize("edit_rules", [False, True])
def test_wave6_active_svi_acl_requires_endpoint_impact(tmp_path, edit_rules):
    fake = ReplayAcl(SVI)
    runtime = make_runtime(tmp_path, fake)
    apply(runtime, fake, req(ACL, KEY4, {"rules": RULES4}, op="create", label="create"))
    binding = SVI + ":ipv4:in"
    if edit_rules:
        apply(runtime, fake, req(ATTACHMENT, binding, {"acl": NAME4}, label="attach"))
    fake.svi_up = True
    table, key, changes = (ACL, KEY4, {"rules": "20 permit ip any any"}) if edit_rules else (
        ATTACHMENT, binding, {"acl": NAME4})
    change = request(table=table, key=key, changes=changes, request_id="wave6-acl")
    before = len(fake.applied_blocks)
    preview = execute.preview(runtime, "lab-nxos", change)
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["endpoint_impact_required"]
    assert len(fake.applied_blocks) == before

    approved = request(table=table, key=key, changes=changes, request_id="wave6-acl", endpoint_impact=key)
    result = apply(runtime, fake, approved)
    assert result["plan"]["endpoint_impact"] == key


@pytest.mark.parametrize(("key", "rules", "canonical", "protocol"), [
    (KEY4, RULES4, CANONICAL4, "ip"),
    (KEY6, RULES6, CANONICAL6, "ipv6"),
])
def test_ordered_create_update_and_undo(tmp_path, key, rules, canonical, protocol):
    fake = ReplayAcl()
    baseline = fake._config()
    runtime = make_runtime(tmp_path, fake)
    created = apply(runtime, fake, req(ACL, key, {"rules": rules}, "create", "create"))
    assert created["plan"]["predicted"] == {"before": None, "after": {"rules": canonical}}
    original = fake._config()
    updated = apply(runtime, fake, req(ACL, key, {"rules": f"20 permit {protocol} any any"}, label="update"))
    assert updated["plan"]["commands"][2:5] == ["no 10", "no 30", f"20 permit {protocol} any any"]
    undo(runtime, fake, updated)
    assert fake._config() == original
    undo(runtime, fake, created)
    assert fake._config() == baseline


def test_undo_recreates_preexisting_empty_acl(tmp_path):
    fake = ReplayAcl()
    header = "ipv6 access-list " + NAME6
    fake.body.append(header)
    fake.saved = fake._config()
    baseline = fake._config()
    runtime = make_runtime(tmp_path, fake)
    removed = apply(runtime, fake, req(ACL, KEY6, {}, "delete", "delete-empty"))
    assert removed["plan"]["predicted"] == {"before": {}, "after": None}
    undo(runtime, fake, removed)
    assert fake._config() == baseline


@pytest.mark.parametrize(("target", "direction", "family", "cli", "name", "rules", "verb"), [
    (PORT, "in", "ipv4", "ip", NAME4, CANONICAL4, "port access-group"),
    (PORT, "in", "ipv6", "ipv6", NAME6, CANONICAL6, "port traffic-filter"),
    (SVI, "in", "ipv4", "ip", NAME4, CANONICAL4, "access-group"),
    (SVI, "out", "ipv6", "ipv6", NAME6, CANONICAL6, "traffic-filter"),
])
def test_binding_apply_and_undo(tmp_path, target, direction, family, cli, name, rules, verb):
    fake = ReplayAcl(target)
    fake.body.extend([f"{cli} access-list {name}", *("  " + rule for rule in rules.split(", "))])
    fake.saved = fake._config()
    baseline = fake._config()
    runtime = make_runtime(tmp_path, fake)
    attached = apply(runtime, fake, req(ATTACHMENT, f"{target}:{family}:{direction}", {"acl": name}))
    command = f"{cli} {verb} {name} {direction}"
    assert command in attached["plan"]["commands"]
    assert command in fake.interface(target)
    undo(runtime, fake, attached)
    assert fake._config() == baseline


def test_binding_preview_refuses_disagreement_with_the_check_account(tmp_path):
    fake = ReplayAcl()
    fake.body.extend(["ip access-list " + NAME4, *("  " + rule for rule in CANONICAL4.split(", "))])
    fake.saved = fake._config()
    runtime = make_runtime(tmp_path, fake)
    fake.read_failure = lambda command: (0, measured("ipv4-pacl_summary") if command.endswith("summary")
                                         else fake.check_query(command))
    preview = execute.preview(runtime, "lab-nxos", req(ATTACHMENT, PORT + ":ipv4:in", {"acl": NAME4}))
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["nxos_acl_readback_unreadable"]
    assert fake.applied_blocks == []


@pytest.mark.parametrize(("node", "family", "cli", "name", "rules"), [
    ("nexus-peer-a", "ipv4", "ip", "copp-system-p-acl-auto-rp",
     "10 permit ip any 224.0.1.39/32, 20 permit ip any 224.0.1.40/32"),
    ("nexus-peer-b", "ipv6", "ipv6", "copp-system-p-acl-vrrp6", "10 permit ipv6 any ff02::12/128"),
])
def test_switch_pair_acl_readback_uses_named_acl_and_summary(node, family, cli, name, rules):
    fake = ReplayAcl()
    command = f"show {cli} access-lists {name}"
    version = family[-1]
    answers = {command: measured(f"{node}__v{version}-acl-shaped"),
               command + " summary": measured(f"{node}__acl{version}-summary")}
    fake.read_failure = lambda query: (0, answers[query])
    plan = {"table": ACL, "key": f"{family}:{name}"}
    assert exec_nxos.observe(fake, plan) == {"rules": rules}


@pytest.mark.parametrize(("reply", "reason"), [
    ("rejected", "nxos_acl_readback_unreadable"),
    ("truncated", "nxos_acl_readback_unreadable"),
    ("timeout", "nxos_acl_read_timeout"),
])
def test_refusal_incomplete_or_timeout_never_writes(tmp_path, reply, reason):
    fake = ReplayAcl()
    fake.body.extend(["ip access-list " + NAME4, *("  " + rule for rule in CANONICAL4.split(", "))])
    fake.saved = fake._config()
    runtime = make_runtime(tmp_path, fake)

    def failure(command):
        if reply == "timeout":
            raise AccessError("query timed out")
        if reply == "rejected":
            return 16, measured("nexus9300v__ip-int-acl")
        answer = fake.check_query(command)
        return 0, answer if command.endswith("summary") else answer.rsplit("\n", 2)[0] + "\n"

    fake.read_failure = failure
    preview = execute.preview(runtime, "lab-nxos", req(ACL, KEY4, {"rules": "40 permit ip any any"}))
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == [reason]
    assert fake.applied_blocks == [] and fake.clean()


@pytest.mark.parametrize(("table", "key", "change", "expected"), [
    (ATTACHMENT, PORT + ":ipv4:out", {"acl": NAME4}, "nxos_acl_unsupported"),
    (ATTACHMENT, PORT + ":ipv6:in", {"acl": NAME4}, "nxos_acl_undefined"),
    (ATTACHMENT, PORT + ":ipv4:in", {"acl": NAME4}, "port_protected"),
    (ACL, KEY4, {"rules": "5 permit ip any any"}, "port_protected"),
])
def test_static_refusals_include_indirectly_protected_port(table, key, change, expected):
    fake = ReplayAcl()
    fake.body.extend(["ip access-list " + NAME4, *("  " + rule for rule in CANONICAL4.split(", "))])
    if table == ACL:
        fake._set(PORT, re.compile("^ip port access-group "), f"ip port access-group {NAME4} in")
    with pytest.raises(Rejected) as caught:
        engine.build_plan("nxos", fake.snapshot().encode(), req(table, key, change),
                          protected={"interface": [PORT]} if "protected" in expected else {})
    assert caught.value.reason_codes == [expected]
    assert fake.applied_blocks == []


def test_untested_firmware_warns():
    fake = ReplayAcl()
    snapshot = fake.snapshot().replace("version 9.3(12)", "version 9.3(13)")
    plan = engine.build_plan("nxos", snapshot.encode(), req(ACL, KEY4, {"rules": RULES4}, "create"))
    assert plan["firmware_support"]["status"] == "untested"
