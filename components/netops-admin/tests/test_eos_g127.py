"""EOS ACL Admin transactions using the measured cEOS 4.36.1F transport."""
from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, gaierror
from types import SimpleNamespace

import pytest

from fake_eos import FakeEos, fixture
from enrollment_helpers import certify
from test_eos import make_runtime, request, steps

from netops_admin import eos_acl, execute
from netops_admin.access import AccessError, DeviceAccess

FIXTURES = Path(__file__).parent / "fixtures" / "eos_g127"
PORT = "Ethernet5"
V4 = "netops-g127-v4"
V6 = "netops-g127-v6"


def raw(name, suffix="txt"):
    return (FIXTURES / f"{name}.{suffix}").read_text()


class MeasuredAclEos(FakeEos):
    def __init__(self):
        super().__init__()
        start, end = self._block("interface " + PORT)
        self.lines[start:end] = raw("interface").splitlines()[:1]
        self.saved = list(self.lines)
        self.answer = None
        self.answer_after_write = None
        self.reject_rule = False
        self.rules_applied = False
        self.inactive_bindings = set()
        self.binding_applied = False
        self.learned_macs[PORT] = 1
        self.management_route_interface = "Management0"

    def scope(self, header):
        if header not in self.lines:
            return None
        start, end = self._block(header)
        return [line.strip() for line in self.lines[start + 1:end]]

    def acl_answer(self, prefix, selection):
        if self.answer is not None:
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
        if self.answer_after_write is not None and self.rules_applied:
            return self.answer_after_write
        answer = json.loads(raw("missing", "json"))
        family = "v4" if prefix == "ip" else "v6"
        for header in self.lines:
            if not header.startswith(prefix + " access-list "):
                continue
            name = header.split()[-1]
            configured = {"Ingress": [], "Egress": []}
            for line in self.lines:
                if not line.startswith("interface "):
                    continue
                interface = line.split()[1]
                for direction, label in (("in", "Ingress"), ("out", "Egress")):
                    if f"{prefix} access-group {name} {direction}" in self.scope(line):
                        configured[label].append({"name": interface})
            if selection.startswith("interface "):
                interface = selection.split()[-1]
                if not any({"name": interface} in values for values in configured.values()):
                    continue
            elif selection != name:
                continue
            lines = self.scope(header)
            row, = json.loads(raw(("binding-" if lines else "empty-") + family, "json"))["aclList"]
            source = {" ".join(item["text"].split()): item for item in row["sequence"]}
            row["name"] = name
            row["sequence"] = []
            for line in lines:
                number, body = line.split(None, 1)
                row["sequence"].append({**source[body], "sequenceNumber": int(number)})
            row["sequenceLength"] = len(lines)
            for direction, values in configured.items():
                row[f"configured{direction}Intfs"] = values
                row[f"active{direction}Intfs"] = [
                    item for item in values
                    if not (self.rules_applied or self.binding_applied)
                    or (item["name"], direction) not in self.inactive_bindings
                ]
            answer["aclList"].append(row)
        return json.dumps(answer)

    def query(self, command):
        match = re.fullmatch(r"show (ip|ipv6) access-lists (.+) \| json", command)
        if match:
            return self.acl_answer(*match.groups())
        match = re.fullmatch(r"show ip route vrf (default|mgmt) 192[.]0[.]2[.]36 [|] json", command)
        if match:
            answer = json.loads(raw("management-route", "json"))
            vrf = answer["vrfs"].pop("default")
            vrf["routes"]["192.0.2.0/24"]["vias"][0]["interface"] = self.management_route_interface
            answer["vrfs"][match[1]] = vrf
            return json.dumps(answer)
        if command == "show interfaces Vlan200 | json":
            return raw("svi-up", "json")
        if command == f"show mac address-table interface {PORT}" and not self.learned_macs[PORT]:
            return raw("mac")
        support = {
            f"show interfaces {PORT} switchport": "switchport",
            f"show interfaces {PORT} status": "status",
            "show lldp neighbors": "lldp",
        }
        return raw(support[command]) if command in support else super().query(command)

    def check_query(self, command):
        if command == "show version":
            self.check_queries.append(command)
            if self.check_unreadable:
                raise AccessError("check account unavailable")
            return fixture("show-version.txt")
        return super().check_query(command)

    def _line(self, line, mode):
        current = mode[0]
        if current == "config" and (match := re.fullmatch(r"(no )?((?:ip|ipv6) access-list \S+)", line)):
            header = match[2]
            if match[1]:
                start, end = self._block(header)
                del self.lines[start:end + 1]
            else:
                if header not in self.lines:
                    at = self.lines.index("end")
                    self.lines[at:at] = [header, "!"]
                mode[0] = "acl:" + header
            self.rules_applied = True
            return ""
        if current.startswith("acl:") and line not in ("end", "exit"):
            if self.reject_rule:
                return "% Invalid input"
            header = current.removeprefix("acl:")
            start, end = self._block(header)
            matching = {int(line.split()[0]): line.strip() for line in self.lines[start + 1:end]}
            if line.startswith("no "):
                del matching[int(line.split()[1])]
            else:
                number = int(line.split()[0])
                if number in matching:
                    return "% Invalid input"
                matching[number] = line.removesuffix(" eq 443") + " eq https" if line.endswith(" eq 443") else line
            self.lines[start + 1:end] = ["   " + matching[number] for number in sorted(matching)]
            return ""
        if current.startswith("interface:") and (
                match := re.fullmatch(r"(no )?(ip|ipv6) access-group (\S+) (in|out)", line)):
            self._set(current.split(":", 1)[1], re.compile(rf"^{match[2]} access-group \S+ {match[4]}$"),
                      None if match[1] else line)
            self.binding_applied = True
            return ""
        return super()._line(line, mode)


def change(table, key, fields, request_id, *, op="update", impact=False):
    return request(table=table, op=op, key=key, changes=fields, request_id=request_id,
                   **({"endpoint_impact": key} if impact else {}))


def ready(runtime, device, req):
    blocks = list(device.applied_blocks)
    preview = execute.preview(runtime, "lab-ceos", req)
    assert preview["result"] == "ready", preview
    assert device.applied_blocks == blocks
    return preview


def confirmed(runtime, req, preview):
    result = execute.apply(runtime, "lab-ceos", req, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert "configuration_saved" in steps(result)
    return result


def undo(runtime, record):
    preview = execute.preview_undo(runtime, record["change_id"], "G127 verify actual restore", issue=True)
    assert preview["result"] == "ready", preview
    result = execute.undo(runtime, record["change_id"], "G127 verify actual restore",
                          expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    return result


@pytest.mark.parametrize(("family", "prefix", "name", "match"), [
    ("ipv4", "ip", V4, "deny tcp host 192.0.2.1 host 192.0.2.2 eq 443"),
    ("ipv6", "ipv6", V6, "deny tcp host 2001:db8:1::1 host 2001:db8:1::2 eq 8443"),
])
def test_create_bind_resequence_and_undo(tmp_path, family, prefix, name, match):
    device = MeasuredAclEos()
    baseline = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    key = f"{family}:{name}"
    create = change(eos_acl.ACL, key, {"rules": f"30 permit {prefix} any any, 10 {match}"},
                    "g127-create", op="create")
    preview = ready(runtime, device, create)
    assert preview["commands"] == ["configure terminal", f"{prefix} access-list {name}",
                                   "10 " + match, f"30 permit {prefix} any any", "exit", "end"]
    created = confirmed(runtime, create, preview)

    slot = f"{PORT}:{family}:in"
    attach = change(eos_acl.BINDING, slot, {"acl": name}, "g127-attach", impact=True)
    attached = confirmed(runtime, attach, ready(runtime, device, attach))
    assert device.scope("interface " + PORT) == [f"{prefix} access-group {name} in"]

    ordered = change(eos_acl.ACL, key, {"rules": f"30 permit {prefix} any any, 20 {match}"},
                     "g127-order", impact=True)
    preview = ready(runtime, device, ordered)
    assert preview["commands"] == ["configure terminal", f"{prefix} access-list {name}",
                                   "no 10", "20 " + match, "exit", "end"]
    reordered = confirmed(runtime, ordered, preview)
    assert device.scope(f"{prefix} access-list {name}")[0].startswith("20 ")
    undo(runtime, reordered)
    assert device.scope(f"{prefix} access-list {name}")[0].startswith("10 ")
    undo(runtime, attached)
    assert device.scope("interface " + PORT) == []
    undo(runtime, created)
    assert device.lines == device.saved == baseline


@pytest.mark.parametrize(("family", "prefix", "name"), [
    ("ipv4", "ip", "netops-g127-empty4"), ("ipv6", "ipv6", "netops-g127-empty6"),
])
def test_delete_and_recreate_existing_empty_acl(tmp_path, family, prefix, name):
    device = MeasuredAclEos()
    empty_header = f"{prefix} access-list {name}"
    device.lines[device.lines.index("end"):device.lines.index("end")] = [empty_header, "!"]
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.ACL, f"{family}:{name}", {}, "g127-delete-empty", op="delete")
    preview = ready(runtime, device, req)
    assert preview["predicted"] == {"before": {}, "after": None}
    record = confirmed(runtime, req, preview)
    assert device.scope(empty_header) is None
    undo(runtime, record)
    assert device.scope(empty_header) == []
    assert device.lines == device.saved


@pytest.mark.parametrize("failure", ["truncated", "refused", "timeout", "wrong-total"])
def test_preview_fail_closed_with_incomplete_operational_read(tmp_path, failure):
    device = MeasuredAclEos()
    runtime = make_runtime(tmp_path, device)
    payload = json.loads(raw("binding-v4", "json"))
    payload["aclList"][0]["sequence"].pop()
    device.answer = {
        "truncated": raw("missing", "json")[:-4], "refused": raw("refused"),
        "timeout": AccessError("query timed out"), "wrong-total": json.dumps(payload),
    }[failure]
    req = change(eos_acl.ACL, f"ipv4:{V4}", {"rules": "30 permit ip any any"}, "g127-read-check", op="create")
    result = execute.preview(runtime, "lab-ceos", req)
    assert result["result"] == "rejected"
    assert ("eos_acl_read_timeout" if failure == "timeout" else "eos_acl_readback_unreadable") in result["reason_codes"]
    assert not device.applied_blocks


@pytest.mark.parametrize(("target", "expected"), [
    ("Management0", "port_management_interface"),
    ("Vlan10", "port_management_interface"),
    ("Ethernet5", "endpoint_impact_required"),
])
def test_binding_refuses_management_and_unacknowledged_link(tmp_path, target, expected):
    device = MeasuredAclEos()
    device.management_route_interface = "Vlan10"
    at = device.lines.index("end")
    device.lines[at:at] = [f"ip access-list {V4}", "   30 permit ip any any", "!"]
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.BINDING, f"{target}:ipv4:in", {"acl": V4}, "g127-protect")
    refused = execute.preview(runtime, "lab-ceos", req)
    assert refused["result"] == "rejected"
    assert expected in refused["reason_codes"]
    assert not device.applied_blocks


def test_failed_operational_readback_leaves_safeguard_to_restore(tmp_path):
    device = MeasuredAclEos()
    baseline = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.ACL, f"ipv4:{V4}", {"rules": "30 permit ip any any"}, "g127-revert", op="create")
    preview = ready(runtime, device, req)
    device.answer_after_write = raw("missing", "json")[:-4]
    record = execute.apply(runtime, "lab-ceos", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted"
    assert device.lines == device.saved == baseline


@pytest.mark.parametrize("configured_reference", [
    ("management ssh", f"   ip access-group {V4} vrf default in"),
    ("interface Management0", f"   ip access-group {V4} in"),
])
def test_acl_rule_edit_refuses_an_indirect_management_reference(tmp_path, configured_reference):
    device = MeasuredAclEos()
    header, line = configured_reference
    if header in device.lines:
        start, _ = device._block(header)
        device.lines.insert(start + 1, line)
    else:
        device.lines[device.lines.index("end"):device.lines.index("end")] = [header, line, "!"]
    device.lines[device.lines.index("end"):device.lines.index("end")] = [
        f"ip access-list {V4}", "   30 permit ip any any", "!"]
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.ACL, f"ipv4:{V4}", {"rules": "30 deny ip any any"}, "g127-guard-reference", impact=True)
    result = execute.preview(runtime, "lab-ceos", req)
    assert result["result"] == "rejected"
    assert set(result["reason_codes"]) & {"port_management_interface", "eos_acl_in_use"}
    assert not device.applied_blocks


@pytest.mark.parametrize("reference,expected", [(False, "ready"), (True, "rejected")])
def test_acl_name_matching_ospf_protocol_is_not_a_reference(tmp_path, reference, expected):
    device = MeasuredAclEos()
    at = device.lines.index("end")
    device.lines[at:at] = ["router ospf 29", "   redistribute connected", "!"]
    if reference:
        device.lines[at:at] = ["management ssh", "   ip access-group ospf vrf default in", "!"]
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.ACL, "ipv4:ospf", {"rules": "30 permit ip any any"}, "g127-ospf-name", op="create")
    result = execute.preview(runtime, "lab-ceos", req)
    assert result["result"] == expected, result
    if reference:
        assert result["reason_codes"] == ["eos_acl_in_use"]
    assert not device.applied_blocks


@pytest.mark.parametrize("family,scenario,expected", [
    ("ipv4", "single", "ready"), ("ipv6", "single", "ready"),
    ("ipv4", "multiple", "port_uplink"), ("ipv4", "empty", "port_uplink"),
    ("ipv4", "offlink", "port_uplink"), ("ipv4", "next-hop", "port_uplink"),
    ("ipv4", "ospf-default", "port_uplink"), ("ipv4", "ospf-tenant", "port_uplink"),
    ("ipv4", "ospf-other-vrf", "ready"), ("ipv4", "ospf-bound-acl", "port_uplink"),
    ("ipv4", "bgp-tenant", "port_uplink"),
    ("ipv4", "incomplete", "eos_acl_readback_unreadable"),
    ("ipv4", "no-ack", "endpoint_impact_required"),
])
def test_connected_routed_acl_requires_one_direct_endpoint(tmp_path, family, scenario, expected):
    from test_eos_g130 import ARP_BEFORE, ND_BEFORE

    version = family[-1]
    vrf = "TENANT" if scenario.startswith(("ospf-", "bgp-")) and scenario != "ospf-default" else "default"
    protocol, prefix, address, acl = (("ip", f"ip arp vrf {vrf} interface ", "198.51.100.1/24", V4)
                                      if version == "4" else
                                      ("ipv6", "ipv6 neighbors vrf default ", "2001:db8:1::1/64", V6))
    # Derived from the recorded ARP/ND result by changing the VLAN and port pair to a routed Ethernet interface.
    data = json.loads(ARP_BEFORE if version == "4" else ND_BEFORE)
    rows = data[f"ipV{version}Neighbors"]
    rows[0]["interface"] = PORT
    if scenario == "multiple":
        rows.append(dict(rows[0], address="198.51.100.12", hwAddress="0000.5e00.5303"))
        data.update(totalEntries=2, dynamicEntries=2)
    elif scenario == "empty":
        rows.clear()
        data.update(totalEntries=0, dynamicEntries=0)
    elif scenario == "offlink":
        rows[0]["address"] = "203.0.113.11"
    elif scenario == "incomplete":
        data.update(totalEntries=2, dynamicEntries=2)

    class RoutedEos(MeasuredAclEos):
        def query(self, command):
            if command == f"show interfaces {PORT} switchport":
                return f"Name: Et5\nSwitchport: Disabled\n"
            if command == f"show {prefix}{PORT} | json":
                return json.dumps(data)
            return super().query(command)

    device = RoutedEos()
    at = device.lines.index(f"interface {PORT}") + 1
    device.lines[at:at] = ["   no switchport", f"   {protocol} address {address}"]
    if vrf != "default":
        device.lines.insert(at + 1, f"   vrf {vrf}")
    if scenario == "ospf-bound-acl":
        device.lines.insert(at + 3, f"   ip access-group {acl} in")
    if vrf != "default":
        at = device.lines.index("end")
        device.lines[at:at] = [f"vrf instance {vrf}", "!", f"ip routing vrf {vrf}"]
    if scenario == "ospf-other-vrf":
        at = device.lines.index("end")
        device.lines[at:at] = ["vrf instance OTHER", "!", "ip routing vrf OTHER"]
    at = device.lines.index("end")
    rule = json.loads(raw("binding-v" + version, "json"))["aclList"][0]["sequence"][-1]
    device.lines[at:at] = [f"{protocol} access-list {acl}", f"   {rule['sequenceNumber']} {rule['text']}", "!"]
    if scenario == "next-hop":
        device.lines.insert(at, "ip route 192.0.2.128/26 198.51.100.11")
    elif scenario.startswith("ospf-"):
        ospf_vrf = {"ospf-default": "", "ospf-other-vrf": " vrf OTHER"}.get(scenario, f" vrf {vrf}")
        device.lines[at:at] = [f"router ospf 29{ospf_vrf}", "   network 198.51.100.0/24 area 0", "!"]
    elif scenario == "bgp-tenant":
        device.lines[at:at] = ["router bgp 64512", "   vrf TENANT", "      neighbor 198.51.100.11 remote-as 64513", "!"]
    device.learned_macs[PORT] = 0
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.BINDING, f"{PORT}:{family}:in", {"acl": acl}, "g127-routed",
                 impact=scenario != "no-ack")
    if scenario == "ospf-bound-acl":
        req = change(eos_acl.ACL, f"{family}:{acl}", {"rules": "20 permit ip any any"}, "g127-routed-rules", impact=True)
    result = execute.preview(runtime, "lab-ceos", req)
    if expected == "ready":
        assert result["result"] == "ready", result
    else:
        assert result["result"] == "rejected" and result["reason_codes"] == [expected], result
    assert not device.applied_blocks


def test_lost_check_login_after_acl_write_returns_the_running_state(tmp_path):
    device = MeasuredAclEos()
    baseline = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.ACL, f"ipv4:{V4}", {"rules": "30 permit ip any any"}, "g127-check-account", op="create")
    preview = ready(runtime, device, req)

    def disconnect(target, commands):
        if f"ip access-list {V4}" in commands:
            target.check_unreadable = True

    device.on_apply = disconnect
    record = execute.apply(runtime, "lab-ceos", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted"
    assert device.lines == device.saved == baseline


@pytest.mark.parametrize(("family", "prefix", "name", "rule", "direction"), [
    ("ipv4", "ip", V4, "30 permit ip any any", "in"),
    ("ipv6", "ipv6", V6, "30 permit ipv6 any any", "out"),
])
def test_apply_reverts_configured_only_binding_on_connected_port(tmp_path, family, prefix, name, rule, direction):
    device = MeasuredAclEos()
    at = device.lines.index("end")
    device.lines[at:at] = [f"{prefix} access-list {name}", f"   {rule}", "!"]
    baseline = device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.BINDING, f"{PORT}:{family}:{direction}", {"acl": name}, "g127-inactive", impact=True)
    preview = ready(runtime, device, req)
    device.inactive_bindings = {(PORT, "Ingress" if direction == "in" else "Egress")}

    record = execute.apply(runtime, "lab-ceos", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted"
    assert "check_identity_failed" in steps(record)
    assert device.lines == device.saved == baseline


@pytest.mark.parametrize("lost_binding", ["inactive", "missing"])
def test_rule_edit_verifies_existing_operational_bindings_after_write(tmp_path, lost_binding):
    device = MeasuredAclEos()
    device.lines[device.lines.index("end"):device.lines.index("end")] = [
        f"ip access-list {V4}", "   30 permit ip any any", "!"]
    start, _ = device._block("interface " + PORT)
    device.lines.insert(start + 1, f"   ip access-group {V4} in")
    baseline = device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.ACL, f"ipv4:{V4}", {"rules": "20 permit ip any any"}, "g127-edit-bound", impact=True)
    preview = ready(runtime, device, req)
    if lost_binding == "inactive":
        device.inactive_bindings = {(PORT, "Ingress")}
    else:
        payload = json.loads(device.acl_answer("ip", V4))
        row, = payload["aclList"]
        row["sequence"][0]["sequenceNumber"] = 20
        row["configuredIngressIntfs"] = row["activeIngressIntfs"] = []
        device.answer_after_write = json.dumps(payload)

    record = execute.apply(runtime, "lab-ceos", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted"
    assert "check_identity_failed" in steps(record)
    assert device.lines == device.saved == baseline


@pytest.mark.parametrize("macs", [0, 1, 2])
def test_connected_binding_requires_evidence_of_one_endpoint(tmp_path, macs):
    device = MeasuredAclEos()
    device.learned_macs[PORT] = macs
    at = device.lines.index("end")
    device.lines[at:at] = [f"ip access-list {V4}", "   30 permit ip any any", "!"]
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.BINDING, f"{PORT}:ipv4:in", {"acl": V4}, "g127-endpoint", impact=True)

    result = execute.preview(runtime, "lab-ceos", req)
    assert result["result"] == ("ready" if macs == 1 else "rejected")
    if macs != 1:
        assert "port_uplink" in result["reason_codes"]
    assert not device.applied_blocks


@pytest.mark.parametrize(("management_vrf", "route_interface", "expected"), [
    ("mgmt", "Management0", "ready"),
    ("default", "Management0", "ready"),
    ("default", "Vlan200", "rejected"),
])
def test_preview_data_svi_uses_actual_management_path(tmp_path, management_vrf, route_interface, expected):
    device = MeasuredAclEos()
    start, _ = device._block("interface Management0")
    vrf_line = [f"   vrf {management_vrf}"] if management_vrf != "default" else []
    device.lines[start + 1:start + 2] = [*vrf_line, "   ip address 192.0.2.53/24"]
    device.management_route_interface = route_interface
    at = device.lines.index("end")
    device.lines[at:at] = [
        "interface Vlan200", "   ip address 198.51.100.1/24", "!",
        f"ip access-list {V4}", "   30 permit ip any any", "!"]
    device.ssh_status = raw("management-ssh").replace(
        "SSH connection limit", "SSHD status for VRF mgmt: enabled\nSSH connection limit")
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(eos_acl.BINDING, "Vlan200:ipv4:in", {"acl": V4}, "g127-data-svi", impact=True)

    preview = execute.preview(runtime, "lab-ceos", req)
    assert preview["result"] == expected, preview
    if expected == "ready":
        assert preview["commands"] == [
            "configure terminal", "interface Vlan200", f"ip access-group {V4} in", "end"]
    else:
        assert "port_management_interface" in preview["reason_codes"]
    assert not device.applied_blocks


@pytest.mark.parametrize(("dns_address", "check_peer", "target", "expected"), [
    ("198.51.100.1", None, "Vlan200", "eos_acl_readback_unreadable"),
    ("198.51.100.1", "198.51.100.36", "Vlan200", "port_management_interface"),
    ("203.0.113.2", None, "Vlan200", "eos_acl_readback_unreadable"),
    ("203.0.113.2", "192.0.2.36", "Vlan200", "eos_acl_readback_unreadable"),
    ("203.0.113.2", "198.51.100.36", "Ethernet5", "port_management_interface"),
    (None, None, "Vlan200", "eos_acl_readback_unreadable"),
    ("192.0.2.53", None, "Vlan200", "ready"),
    ("203.0.113.2", "198.51.100.36", "Vlan200", "ready"),
])
def test_acl_checks_independent_ssh_path_for_dns_target(tmp_path, monkeypatch, dns_address, check_peer, target, expected):
    # Derived from the measured SSH sessions, management route and SVI fixtures for split management and data VRFs.
    class SplitSshEos(MeasuredAclEos):
        check_credential = SimpleNamespace(login="netops-ro")
        resolve_addresses = DeviceAccess.resolve_addresses

        def query(self, command):
            if command == "show users detail | json" and check_peer:
                data = json.loads(super().query(command))
                writer = next(iter(data["vtys"].values()))
                data["vtys"]["8582"] = dict(writer, username=self.check_credential.login, remoteAddress=check_peer)
                return json.dumps(data)
            if command == "show ip route vrf default 192.0.2.36 | json":
                return json.dumps({"vrfs": {"default": {"routes": {}}}})
            if match := re.fullmatch(r"show ip route vrf (default|mgmt) 198[.]51[.]100[.]36 [|] json", command):
                vrf = match[1]
                route = json.loads(raw("management-route", "json"))["vrfs"]["default"]["routes"]["192.0.2.0/24"]
                route["vias"][0]["interface"] = PORT
                routes = {"198.51.100.36/32": route} if vrf == "default" else {}
                return json.dumps({"vrfs": {vrf: {"routes": routes}}})
            return super().query(command)

    def resolve(host, port, *, type):
        assert (host, port, type) == ("check.example.test", None, SOCK_STREAM)
        if dns_address is None:
            raise gaierror("test resolver failure")
        return [(AF_INET, SOCK_STREAM, 0, "", (dns_address, 0))]

    monkeypatch.setattr("netops_admin.access.getaddrinfo", resolve)
    device = SplitSshEos()
    start, _ = device._block("interface Management0")
    device.lines[start + 1:start + 2] = ["   vrf mgmt", "   ip address 192.0.2.53/24"]
    start, _ = device._block(f"interface {PORT}")
    device.lines[start + 1:start + 1] = ["   no switchport", "   ip address 203.0.113.130/30"]
    at = device.lines.index("end")
    device.lines[at:at] = [
        "vrf instance mgmt", "!", "ip routing vrf mgmt",
        "interface Vlan200", "   ip address 198.51.100.1/24", "!",
        "interface Loopback20", "   ip address 203.0.113.2/32", "!",
        "ip route 198.51.100.36/32 203.0.113.129",
        f"ip access-list {V4}", "   30 permit ip any any", "!",
    ]
    device.ssh_status = raw("management-ssh").replace(
        "SSH connection limit", "SSHD status for VRF mgmt: enabled\nSSH connection limit")
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    cfg = runtime.config.devices["lab-ceos"]
    runtime.config.devices["lab-ceos"] = replace(cfg, check_address="check.example.test")
    certify(runtime, device, "lab-ceos")
    req = change(eos_acl.BINDING, f"{target}:ipv4:in", {"acl": V4}, "g127-check-dns", impact=True)

    result = execute.preview(runtime, "lab-ceos", req)
    if expected == "ready":
        assert result["result"] == "ready", result
    else:
        assert result["result"] == "rejected" and result["reason_codes"] == [expected], result
    assert "show version" in device.check_queries
    assert not device.applied_blocks
