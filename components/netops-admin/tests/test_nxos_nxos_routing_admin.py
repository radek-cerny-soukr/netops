"""Replay the NXOS-ROUTING-ADMIN readback and configuration from a Nexus 9000v running NX-OS 9.3(12)."""
from pathlib import Path
import re

import pytest

from fake_nxos import FakeNxos
from netops_admin import engine, exec_nxos, execute, nxos, prediction
from netops_admin.errors import Rejected
from test_nxos import make_runtime, request, steps
from approved_apply import approved_apply

FIXTURES = Path(__file__).parent / "fixtures" / "nxos_nxos_routing_admin"
ROUTE = "198.51.100.0/24"
V6 = "2001:db8::/32"
HOP = "192.0.2.250"
LOOP = "loopback900"
ROUTE_COMMAND = "ip route " + ROUTE + " " + HOP


def measured(name):
    return (FIXTURES / (name + ".txt")).read_text(encoding="utf-8")


def blocks(content):
    """Separate the top-level statements and their indented lines from the targeted capture."""
    result = {}
    for line in content.splitlines():
        if not line:
            continue
        if line.startswith("  "):
            result[header].append(line)
        else:
            header = line
            result[header] = [line]
    return result


class ReplayNxos(FakeNxos):
    def __init__(self, checkpoint="base"):
        super().__init__()
        self.captured = blocks(measured("interfaces-config"))
        self.svi_status = measured("interfaces-svi")
        if checkpoint != "base":
            self.body.extend(self.captured["vlan 1,10,20,3900"])
            self.body.append("vrf context nxos-routing-admin")
        self.saved = self._config()

    def _config_line(self, words, mode):
        line = " ".join(words)
        route = ROUTE_COMMAND + " 19"
        if line == route:
            self.body.extend(self.captured[route])
        elif line == "no " + ROUTE_COMMAND:
            self.body.remove(route)
        elif line == "interface " + LOOP:
            self.body.append("interface " + LOOP)
            mode[0] = "interface:" + LOOP
        elif line == "no interface " + LOOP:
            first, last = self._block("interface " + LOOP)
            del self.body[first:last]
        else:
            return super()._config_line(words, mode)
        return ""

    def _interface_line(self, name, words, line):
        if name == LOOP and "  " + line in self.captured["interface " + LOOP]:
            first, last = self._block("interface " + LOOP)
            self.body.insert(last, "  " + line)
            return ""
        return super()._interface_line(name, words, line)

    def query(self, command):
        if command == "show interface vlan 3900" and self.interface("Vlan3900") is not None:
            self.queries.append(command)
            return self.svi_status
        if command == "show feature | include ^dhcp":
            return measured("feature-dhcp-disabled")
        return super().query(command)

    def check_query(self, command):
        if self.check_override and command in self.check_override:
            return super().check_query(command)
        if command == "show ip static-route vrf default":
            self.check_queries.append(command)
            return measured(("routes" if ROUTE_COMMAND + " 19" in self.body else "base") + "-routes4")
        if command == "show ipv6 static-route vrf default":
            self.check_queries.append(command)
            return measured("base-routes6")
        if command == "show ip static-route vrf nxos-routing-admin":
            self.check_queries.append(command)
            return measured("routes-routes-vrf4")
        if command == "show interface loopback 900":
            self.check_queries.append(command)
            return measured("interfaces-loop" if self.interface(LOOP) else "base-loop")
        if command == "show ipv6 interface loopback 900":
            self.check_queries.append(command)
            return measured("interfaces-loop6")
        return super().check_query(command)


def layer3_request(table, key, changes, op="create"):
    return request(table=table, key=key, op=op, changes=changes)


@pytest.mark.parametrize("key, hop, interface", [
    ("2001:db8:3900::/64", "2001:db8:ffff::fe", "Vlan3900"),
    ("192.0.2.8/29", HOP, "Vlan3900"),
    ("192.0.2.222/32", HOP, "loopback900"),
    ("2001:db8:3900:0:8000::/65", "2001:db8:ffff::fe", "Vlan3900"),
    ("vrf:nxos-routing-admin:192.0.2.8/29", HOP, None),
    (ROUTE, HOP, None),
])
def test_static_route_preview_checks_connected_svi_and_loopback(tmp_path, key, hop, interface):
    fake = ReplayNxos("interfaces")
    for name in ("interface Vlan3900", "interface " + LOOP):
        fake.body.extend(fake.captured[name])
    fake.saved = fake._config()
    runtime = make_runtime(tmp_path, fake)
    result = execute.preview(runtime, "lab-nxos", layer3_request("static-route", key, {"next-hop": hop}))
    if interface is None:
        assert result["result"] == "ready", result
    else:
        assert result["result"] == "rejected", result
        assert result["reason_codes"] == ["unspecified_refusal"]
        assert "overlaps" in result["reasons"][0] and interface in result["reasons"][0]
    assert not fake.applied_blocks


def test_static_route_preview_updates_ipv6_summary(tmp_path):
    fake = ReplayNxos()
    fake.body.extend(measured("interfaces-config").splitlines())
    fake.check_override = {"show ipv6 static-route vrf default": measured("routes-routes6")}
    fake.saved = fake._config()
    runtime = make_runtime(tmp_path, fake)
    req = layer3_request("static-route", V6, {"distance": 1}, "update")
    result = execute.preview(runtime, "lab-nxos", req)
    assert result["result"] == "ready", result
    assert result["predicted"]["before"]["distance"] == "21"
    assert result["predicted"]["after"] == {"next-hop": "2001:db8:ffff::fe"}  # Default distance 1 is implicit.
    assert result["commands"] == ["configure terminal", "ipv6 route 2001:db8::/32 2001:db8:ffff::fe", "end"]
    assert not fake.applied_blocks


@pytest.mark.parametrize("key, hop", [
    ("0.0.0.0/1", HOP), ("128.0.0.0/1", HOP),
    ("::/1", "2001:db8:ffff::fe"), ("8000::/1", "2001:db8:ffff::fe"),
    ("vrf:nxos-routing-admin:128.0.0.0/1", HOP),
])
def test_split_default_route_preview_is_protected(tmp_path, key, hop):
    fake = ReplayNxos("interfaces")
    runtime = make_runtime(tmp_path, fake)
    result = execute.preview(runtime, "lab-nxos", layer3_request("static-route", key, {"next-hop": hop}))
    assert result["result"] == "rejected", result
    assert result["reason_codes"] == ["port_management_interface"]
    assert "split default" in result["reasons"][0]
    assert not fake.applied_blocks


@pytest.mark.parametrize("table, key, changes, own_peer, code", [
    ("l3-interface", "Vlan3900", {"admin-state": "disabled"}, "192.0.2.3", "port_management_interface"),
    ("l3-interface", "Vlan3900", {"ipv6-address": None}, "2001:db8:3900::3", "port_management_interface"),
    ("dhcp-relay", "Vlan3900:192.0.2.249", {}, "192.0.2.3", "port_management_interface"),
    ("l3-interface", "Vlan3900", {"admin-state": "disabled"}, None, "port_usage_unreadable"),
    ("l3-interface", "Vlan3900", {"admin-state": "disabled"}, "192.0.2.36", None),
])
def test_svi_preview_checks_own_ssh_session(tmp_path, table, key, changes, own_peer, code):
    fake = ReplayMeasuredChanges()
    runtime = make_runtime(tmp_path, fake)
    fake.set_svi_readback(up=True)
    users = fake.query("show users")
    header, own = users.splitlines()
    own = own.replace("192.0.2.36", own_peer) if own_peer else ""
    # An unrelated SSH session inside the SVI subnet does not identify Admin's path.
    foreign = users.splitlines()[1].replace("192.0.2.36", "192.0.2.4").removesuffix(" *")
    fake.interactive_answers["show users"] = "\n".join((header, foreign, own))
    if own_peer:
        fake.interactive_answers["show sockets connection tcp foreign " + own_peer] = (
            measured("ssh-sockets-management").replace("198.51.100.60", own_peer)
            .replace("management", "default"))
    req = layer3_request(table, key, changes, "create" if table == "dhcp-relay" else "update")
    result = execute.preview(runtime, "lab-nxos", req)
    assert result["result"] == ("rejected" if code else "ready"), result
    assert result["reason_codes"] == ([code] if code else [])
    assert not fake.applied_blocks


@pytest.mark.parametrize("admin_up, oper_up, peer, changes", [
    pytest.param(False, False, "198.51.100.60", {"admin-state": "enabled"}, id="shutdown"),
    pytest.param(True, False, "192.0.2.3", {"admin-state": "disabled"}, id="protocol-down"),
    pytest.param(True, True, "198.51.100.60", {"admin-state": "disabled"}, id="management-vrf"),
])
def test_svi_preview_ignores_inactive_or_other_vrf(tmp_path, admin_up, oper_up, peer, changes):
    fake = ReplayMeasuredChanges()
    if peer == "198.51.100.60":
        fake._set("Vlan3900", re.compile(r"^ip address "), "ip address 198.51.100.1/24")
    if not admin_up:
        fake._set("Vlan3900", re.compile(r"^no shutdown$"), "shutdown")
    fake.saved = fake._config()
    fake.set_svi_readback(up=oper_up)
    runtime = make_runtime(tmp_path, fake)
    fake.interactive_answers["show users"] = fake.query("show users").replace("192.0.2.36", peer)
    fake.interactive_answers["show sockets connection tcp foreign " + peer] = measured("ssh-sockets-management")
    req = layer3_request("l3-interface", "Vlan3900", changes, "update")
    result = execute.preview(runtime, "lab-nxos", req)
    assert result["result"] == "ready", result
    assert not fake.applied_blocks


@pytest.mark.parametrize("req, command", [
    (layer3_request("static-route", ROUTE, {"next-hop": HOP, "distance": 19}), ROUTE_COMMAND + " 19"),
    (layer3_request("l3-interface", LOOP, {"ipv4-address": "192.0.2.222/32", "ipv6-address": "2001:db8:900::1/128"}),
     "interface " + LOOP),
])
def test_preview_apply_readback_and_undo(tmp_path, monkeypatch, req, command):
    fake = ReplayNxos()
    monkeypatch.setattr(exec_nxos, "PAUSE", fake.advance)
    runtime = make_runtime(tmp_path, fake)
    before = fake._config()
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "ready", preview
    assert command in preview["commands"]
    assert fake.applied_blocks == [] and fake._config() == before
    applied = execute.apply(runtime, "lab-nxos", req, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", (applied.get("reason"), steps(applied))
    assert "check_identity_passed" in steps(applied)
    assert fake._config() != before
    undone = execute.undo(runtime, applied["change_id"], "return to the measured baseline")
    assert undone["result"] == "confirmed", (undone.get("reason"), steps(undone))
    assert "check_identity_passed" in steps(undone)
    assert fake.clean() and fake._config() == before


def test_incomplete_readback_returns_running_configuration(tmp_path, monkeypatch):
    fake = ReplayNxos()
    def truncate_after_write(target, line):
        if line == ROUTE_COMMAND + " 19":
            target.check_override = {"show ip static-route vrf default": measured("base-routes4").splitlines()[0]}

    fake.on_line = truncate_after_write
    monkeypatch.setattr(exec_nxos, "PAUSE", fake.advance)
    before = fake._config()
    runtime = make_runtime(tmp_path, fake)
    req = layer3_request("static-route", ROUTE, {"next-hop": HOP, "distance": 19})
    result = approved_apply(runtime, "lab-nxos", req)
    assert result["result"] == "reverted"
    assert "check_identity_failed" in steps(result)
    assert fake.clean() and fake._config() == before


@pytest.mark.parametrize("file, key, value", [
    ("routes-routes4", ROUTE, {"next-hop": HOP}),
    ("routes-routes6", V6, {"next-hop": "2001:db8:ffff::fe", "distance": "21"}),
    ("routes-routes-vrf4", "vrf:nxos-routing-admin:" + ROUTE, {"next-hop": HOP}),
    ("routes-routes-vrf6", "vrf:nxos-routing-admin:" + V6, {"next-hop": "2001:db8:ffff::fe", "distance": "23"}),
    ("base-routes4", ROUTE, None),
    ("base-routes6", V6, None),
])
def test_route_observation_from_cli(file, key, value):
    assert exec_nxos.route_readback(measured(file), key) == value


def test_route_distance_update_and_profile_prediction():
    fake = ReplayNxos()
    fake.body.extend(measured("routes-config").splitlines())
    req = layer3_request("static-route", ROUTE, {"distance": None}, "update")
    plan = engine.build_plan("nxos", fake.running().encode(), req)
    assert plan["commands"] == ["configure terminal", ROUTE_COMMAND, "end"]
    assert plan["inverse"] == ["configure terminal", ROUTE_COMMAND + " 19", "end"]
    expected = prediction.snapshot_after(fake.running(), plan)
    assert engine.verify(plan, expected.encode())["result"] == "match"
    for line in measured("routes-config").splitlines():
        fake.body.remove(line)
    fake.body.extend(measured("update-config").splitlines())
    # Keep only the independently measured route statements and the VRF they belong to.
    for header, block in blocks(measured("update-config")).items():
        if not header.startswith(("ip route ", "ipv6 route ", "vrf context ")):
            for line in block:
                fake.body.remove(line)
    assert engine.verify(plan, fake.running().encode())["result"] == "mismatch"  # IPv6 distance also changed


def test_loopback_replacement_and_svi_addresses_from_config():
    before, after = FakeNxos(), FakeNxos()
    before.body.extend(measured("interfaces-config").splitlines())
    after.body.extend(measured("interfaces-config").splitlines())
    start, end = after._block("interface " + LOOP)
    after.body[start:end] = blocks(measured("update-config"))["interface " + LOOP]
    req = layer3_request("l3-interface", LOOP, {"ipv4-address": "192.0.2.223/32",
                                               "ipv6-address": "2001:db8:900::2/128"}, "update")
    plan = engine.build_plan("nxos", before.running().encode(), req)
    assert plan["commands"][2:-1] == ["no ip address 192.0.2.222/32", "ip address 192.0.2.223/32",
                                      "no ipv6 address 2001:db8:900::1/128", "ipv6 address 2001:db8:900::2/128"]
    assert engine.verify(plan, after.running().encode())["result"] == "match"
    svi = nxos.load(before.running(), None).entries(nxos.L3_TABLE)["Vlan3900"]
    assert svi.attributes == {"ipv4-address": "192.0.2.1/28", "ipv6-address": "2001:db8:3900::1/64"}


def test_dhcp_disabled_refuses_without_write(tmp_path):
    fake = ReplayNxos("interfaces")
    fake.body.extend(fake.captured["interface Vlan3900"])
    fake.saved = fake._config()
    runtime = make_runtime(tmp_path, fake)
    req = layer3_request("dhcp-relay", "Vlan3900:192.0.2.249", {"vrf": "nxos-routing-admin"})
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["reason_codes"] == ["dhcp_feature_disabled"]
    assert fake.applied_blocks == []
    assert nxos.cli_error(measured("relay-write")) == "% Invalid command at '^' marker."
    with pytest.raises(Rejected):
        exec_nxos.relay_state(measured("base-relay"), req.key)


@pytest.mark.parametrize("table, key, changes", [
    ("l3-interface", "Vlan3900", {"ipv4-address": "192.0.2.1/28"}),
    ("l3-interface", "loopback1200", {}),
    ("static-route", "vrf:missing:" + ROUTE, {"next-hop": HOP}),
    ("static-route", ROUTE, {"next-hop": "2001:db8::1"}),
])
def test_invalid_targets_refused(table, key, changes):
    with pytest.raises(Rejected):
        engine.build_plan("nxos", FakeNxos().running().encode(), layer3_request(table, key, changes))


def test_version_support_warns_without_blocking():
    raw = FakeNxos().running().replace("9.3(12)", "9.3(11)").encode()
    plan = engine.build_plan("nxos", raw, layer3_request("static-route", ROUTE, {"next-hop": HOP}))
    assert plan["firmware_support"]["status"] == "untested"
    assert ROUTE_COMMAND in plan["commands"]


PORT = "Ethernet1/3"
PORT_IP = "192.0.2.17/28"
PORT_ADDRESS = re.compile(r"^ip address ")
RELAY_KEY = "Vlan3900:192.0.2.249"
RELAY_QUERY = "show ip dhcp relay address"
DHCP_CONFIG = "show running-config dhcp"


class ReplayMeasuredChanges(ReplayNxos):
    def __init__(self):
        super().__init__("interfaces")
        self.body.extend(self.captured["interface Vlan3900"])
        self.body.append("feature dhcp")
        self._port_block("l2-before")
        self.relay_config_override = None
        self.interactive_answers = {}
        self.saved = self._config()

    def set_svi_readback(self, *, up):
        headline, detail = measured("interfaces-svi").split("\n", 1)
        if up:
            headline = measured("svi-up").strip().replace("Vlan20 is", "Vlan3900 is")
        elif "shutdown" in self.interface("Vlan3900"):
            headline = headline.replace("VLAN/BD is down", "Administratively down")
        address = next(line.split()[2] for line in self.interface("Vlan3900") if line.startswith("ip address "))
        self.svi_status = headline + "\n" + detail.replace("192.0.2.1/28", address)
        self.check_override = {"show interface vlan 3900": self.svi_status,
                               "show ipv6 interface vlan 3900": measured("interfaces-svi6")}

    def with_interactive_reader(self, spec, inspect):
        return inspect(self.query)

    def _port_block(self, state):
        start, end = self._block("interface " + PORT)
        self.body[start:end] = blocks(measured("port-" + state + "-config"))["interface " + PORT]

    def _relay_capture(self):
        for state in ("default", "vrf"):
            line = next(line.strip() for line in measured("relay-" + state + "-config").splitlines()
                        if line.strip().startswith("ip dhcp relay address "))
            if line in self.interface("Vlan3900"):
                return state
        return "empty"

    def _interface_line(self, name, words, line):
        if name == "Vlan3900" and words[:4] == ["ip", "dhcp", "relay", "address"]:
            self._set(name, nxos.RELAY, line)
            return ""
        if name == "Vlan3900" and words[:5] == ["no", "ip", "dhcp", "relay", "address"]:
            assert line[3:] in self.interface(name)
            self._set(name, nxos.RELAY)
            return ""
        if name == PORT:
            if line == "no switchport":
                self._port_block("l3-after")
                self._set(name, PORT_ADDRESS)
                return ""
            if line == "ip address " + PORT_IP:
                self._port_block("l3-after")
                return ""
            if line == "no ip address " + PORT_IP:
                self._set(name, PORT_ADDRESS)
                return ""
            if line == "switchport":
                self._port_block("l2-after")
                return ""
        return super()._interface_line(name, words, line)

    def query(self, command):
        if command in self.interactive_answers:
            self.queries.append(command)
            return self.interactive_answers[command]
        if command == "show feature | include ^dhcp":
            return measured("feature-dhcp-enabled")
        if command == DHCP_CONFIG:
            self.queries.append(command)
            return measured(self.relay_config_override or "relay-" + self._relay_capture() + "-config")
        if command == "show interface " + PORT + " status":
            self.queries.append(command)
            if "no switchport" in self.interface(PORT):
                return measured("port-l3-after-status")
            return measured("port-l2-before-status")
        return super().query(command)

    def check_query(self, command):
        if command not in (self.check_override or {}):
            if command == RELAY_QUERY:
                self.check_queries.append(command)
                return measured("relay-" + self._relay_capture() + "-table")
            state = "l3-after" if "no switchport" in self.interface(PORT) else "l2-after"
            for suffix in ("", " status", " switchport"):
                if command == "show interface " + PORT + suffix:
                    self.check_queries.append(command)
                    return measured("port-" + state + "-" + (suffix.strip() or "interface"))
        return super().check_query(command)


@pytest.mark.parametrize("changes", [{}, {"vrf": "nxos-routing-admin"}])
def test_measured_relay_preview_apply_and_undo(tmp_path, monkeypatch, changes):
    fake = ReplayMeasuredChanges()
    monkeypatch.setattr(exec_nxos, "PAUSE", fake.advance)
    runtime = make_runtime(tmp_path, fake)
    original = fake._config()
    req = layer3_request("dhcp-relay", RELAY_KEY, changes)
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "ready", preview
    assert fake._config() == original and not fake.applied_blocks
    applied = execute.apply(runtime, "lab-nxos", req, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed" and "check_identity_passed" in steps(applied)
    assert applied["plan"]["predicted"]["after"] == changes
    assert RELAY_QUERY in fake.check_queries and DHCP_CONFIG in fake.queries
    undone = execute.undo(runtime, applied["change_id"], "return the DHCP relay address")
    assert undone["result"] == "confirmed" and "check_identity_passed" in steps(undone)
    assert fake._config() == original and fake.clean()


def test_conflicting_measured_relay_readbacks_refuse_before_write(tmp_path):
    fake = ReplayMeasuredChanges()
    fake.relay_config_override = "relay-vrf-config"
    runtime = make_runtime(tmp_path, fake)
    runtime.simulate_unmeasured_profiles = True
    req = layer3_request("dhcp-relay", RELAY_KEY, {"vrf": "nxos-routing-admin"})
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["port_usage_unreadable"]
    assert not fake.applied_blocks


def test_routed_port_predicts_measured_implicit_shutdown_and_undo(tmp_path, monkeypatch):
    fake = ReplayMeasuredChanges()
    monkeypatch.setattr(exec_nxos, "PAUSE", fake.advance)
    runtime = make_runtime(tmp_path, fake)
    before = fake._config()
    req = layer3_request("l3-interface", PORT, {"mode": "routed", "ipv4-address": PORT_IP}, "update")
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", "interface " + PORT,
                                   "no switchport", "ip address " + PORT_IP, "end"]
    applied = execute.apply(runtime, "lab-nxos", req, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed" and "check_identity_passed" in steps(applied)
    assert applied["plan"]["predicted"]["after"] == {
        "mode": "routed", "ipv4-address": PORT_IP, "admin-state": "disabled",
    }
    assert fake.interface(PORT) == ["no switchport", "ip address " + PORT_IP]
    undone = execute.undo(runtime, applied["change_id"], "return the measured L2 configuration")
    assert undone["result"] == "confirmed" and "check_identity_passed" in steps(undone)
    assert fake._config() == before and fake.clean()


def test_routed_port_refuses_conversion_when_l2_access_vlan_would_be_lost(tmp_path):
    fake = ReplayMeasuredChanges()
    fake._port_block("l2-access-before")
    fake.saved = fake._config()
    before = fake._config()
    req = layer3_request("l3-interface", PORT, {"mode": "routed", "ipv4-address": PORT_IP}, "update")
    runtime = make_runtime(tmp_path, fake)
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "rejected" and "discard" in " ".join(preview["reasons"])
    with pytest.raises(Rejected, match="discard"):
        approved_apply(runtime, "lab-nxos", req)
    assert fake._config() == before and not fake.applied_blocks


# ---- NXOS-ROUTING-ADMIN r3: address conflicts measured on nexus9300v (private measurement record) ----

def conflict_device():
    """The measured SVI Vlan3900 (192.0.2.1/28, 2001:db8:3900::1/64) next to the free Ethernet1/3."""
    fake = ReplayMeasuredChanges()
    fake.saved = fake._config()
    return fake


def refused_without_write(tmp_path, fake, req, codes=None):
    before = fake._config()
    runtime = make_runtime(tmp_path, fake)
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "rejected", preview
    if codes is not None:
        assert preview["reason_codes"] == codes
    with pytest.raises(Rejected):
        approved_apply(runtime, "lab-nxos", req)
    assert fake._config() == before and not fake.applied_blocks
    return preview


# The anonymized baseline keeps loopback0 at 192.0.2.5/32, inside the measured 192.0.2.0/28 of Vlan3900.
@pytest.mark.parametrize("key, changes, op, other", [
    (LOOP, {"ipv4-address": "192.0.2.2/28"}, "create", "loopback0"),         # NX-OS: overlapping network ...
    (LOOP, {"ipv4-address": "192.0.2.2/32"}, "create", "Vlan3900"),          # NX-OS: % ... overlaps with ... Vlan3900
    (LOOP, {"ipv6-address": "2001:db8:3900::2/64"}, "create", "Vlan3900"),   # NX-OS: Subnet already configured ...
    (PORT, {"mode": "routed", "ipv4-address": "192.0.2.9/29"}, "update", "Vlan3900"),
])
def test_overlapping_interface_address_refused_in_preview(tmp_path, key, changes, op, other):
    preview = refused_without_write(tmp_path, conflict_device(), layer3_request("l3-interface", key, changes, op))
    assert "overlaps" in " ".join(preview["reasons"]) and "interface %s " % other in " ".join(preview["reasons"])
    assert "Subnet already configured on interface Vlan3900" in measured("l3-conflicts-write")


def test_same_subnet_in_another_vrf_is_accepted_as_measured():
    fake = conflict_device()
    req = layer3_request("l3-interface", "loopback901", {"vrf": "nxos-routing-admin", "ipv4-address": "192.0.2.2/28"})
    plan = engine.build_plan("nxos", fake.running().encode(), req)
    assert plan["commands"][1:4] == ["interface loopback901", "vrf member nxos-routing-admin", "ip address 192.0.2.2/28"]


def test_interface_networks_include_management_interface():
    snapshot = nxos.load(conflict_device().running(), None)
    found = {(name, vrf, str(network)) for name, vrf, network in nxos.interface_networks(snapshot)}
    assert ("mgmt0", "management", "198.51.100.0/24") in found
    assert ("Vlan3900", None, "192.0.2.0/28") in found and ("Vlan3900", None, "2001:db8:3900::/64") in found
    assert all(name != "Vlan3900" for name, _, _ in nxos.interface_networks(snapshot, skip="Vlan3900"))


class ConnectedRoutedPort(ReplayMeasuredChanges):
    """Ethernet1/3 as a routed port: "connected" = the measured up port (no switchport, ip address, no shutdown),
    "disabled" = the measured port right after the conversion (implicit shutdown)."""

    def __init__(self, state="connected"):
        super().__init__()
        self.state = "l3-connected" if state == "connected" else "l3-after"
        self._port_block(self.state)
        self.saved = self._config()

    def _answer(self, command):
        for suffix in (" status", ""):
            if command == "show interface " + PORT + suffix:
                return measured("port-" + self.state + "-" + (suffix.strip() or "interface"))
        return None

    def query(self, command):
        answer = self._answer(command)
        if answer is not None:
            self.queries.append(command)
            return answer
        return super().query(command)

    def check_query(self, command):
        answer = self._answer(command)
        if answer is not None:
            self.check_queries.append(command)
            return answer
        return super().check_query(command)


@pytest.mark.parametrize("changes", [{"ipv4-address": "192.0.2.21/28"}, {"ipv4-address": None},
                                     {"ipv6-address": "2001:db8:13::1/64"}])
def test_address_change_on_connected_routed_port_refused(tmp_path, changes):
    fake = ConnectedRoutedPort()
    refused_without_write(tmp_path, fake, layer3_request("l3-interface", PORT, changes, "update"), ["port_uplink"])
    assert "show interface " + PORT + " status" in fake.queries


def test_address_change_on_disabled_routed_port_checks_lldp(tmp_path):
    fake = ConnectedRoutedPort("disabled")
    fake.lldp_extra.append("Eth1/3")
    req = layer3_request("l3-interface", PORT, {"ipv4-address": "192.0.2.21/28"}, "update")
    refused_without_write(tmp_path, fake, req, ["port_lldp_neighbor"])


def test_address_change_on_unused_routed_port_is_ready(tmp_path):
    fake = ConnectedRoutedPort("disabled")
    runtime = make_runtime(tmp_path, fake)
    req = layer3_request("l3-interface", PORT, {"ipv4-address": "192.0.2.21/28"}, "update")
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", "interface " + PORT, "no ip address 192.0.2.17/28",
                                   "ip address 192.0.2.21/28", "end"]


@pytest.mark.parametrize("address", ["192.0.2.32/28", "192.0.2.47/28"])
def test_network_and_broadcast_interface_address_refused(address):
    # NX-OS: "All 0s host part is invalid" / "All 1s host part is invalid"
    req = layer3_request("l3-interface", LOOP, {"ipv4-address": address})
    with pytest.raises(Rejected, match="host address"):
        engine.build_plan("nxos", conflict_device().running().encode(), req)


@pytest.mark.parametrize("address", ["192.0.2.32/31", "192.0.2.33/32"])
def test_point_to_point_and_host_addresses_stay_valid(address):
    req = layer3_request("l3-interface", LOOP, {"ipv4-address": address})
    plan = engine.build_plan("nxos", conflict_device().running().encode(), req)
    assert "ip address " + address in plan["commands"]


def test_relay_default_vrf_name_refused(tmp_path):
    # NX-OS stores "use-vrf default" as a relay without VRF, so the literal line would never read back.
    assert "  ip dhcp relay address 192.0.2.249" in measured("relay-use-vrf-default-config").splitlines()
    req = layer3_request("dhcp-relay", RELAY_KEY, {"vrf": "default"})
    preview = refused_without_write(tmp_path, conflict_device(), req)
    assert "omit" in " ".join(preview["reasons"])


@pytest.mark.parametrize("key, hop", [(ROUTE, "192.0.2.1"), ("2001:db8:77::/48", "2001:db8:3900::1")])
def test_route_next_hop_on_own_interface_address_refused(tmp_path, key, hop):
    # NX-OS: "ipv4 Nexthop: cannot be local address in same VRF"
    preview = refused_without_write(tmp_path, conflict_device(), layer3_request("static-route", key, {"next-hop": hop}))
    assert "Vlan3900" in " ".join(preview["reasons"])
