"""SWITCH-AGGREGATION Admin MCP with device responses captured on ExtremeXOS."""
from pathlib import Path
import re
import shlex

import pytest

from fake_exos import FakeExos
from netops_admin import engine, exos, exos_g44
from netops_admin.request import parse_request
from test_exos_switch_vlan_admin import args, audit_policy, preview_apply, setup, undo
from test_mcp_server import call


FIXTURES = Path(__file__).parent / "fixtures" / "exos_switch_aggregation"
HELPER_EXOS = FIXTURES.parents[3] / "netops-helper/tests/fixtures/real/exos"


def reading(name):
    return (FIXTURES / name).read_text()


class Links(FakeExos):
    """Execute only the measured commands, returning the corresponding captured response."""

    def __init__(self):
        super().__init__()
        self.phase = "before"
        self.mlag = False
        self.truncated = False
        self.stp = False
        self.active_stp_port = False
        self.stp_phase = "stp"
        self.stp_lines = []
        self.vlans["g44probe"] = {"tag": "3944"}

    def snapshot(self):
        base = super().snapshot()
        extra = reading(self.phase + "__vsc.out").splitlines()[1:]
        if self.stp:
            extra.append("configure vlan g44probe add ports 10 untagged")
        base = base.replace("# Module ems configuration.", "\n".join(extra) + "\n# Module ems configuration.")
        base += "# Module vsm configuration.\n"
        if self.mlag:
            base += "create mlag peer peerA\nconfigure mlag peer peerA ipaddress 192.0.2.2 vr VR-Default\n"
            base += "enable mlag port 5 peer peerA id 104\n"
        base += self.stp_module() + "# Module elrp configuration.\n"
        return base

    def stp_module(self):
        if not self.stp:
            return "# Module stp configuration.\n"
        defaults = reading("stp__ssc.out")
        measured = reading("stp-port-set__ssc.out")
        retained = [line for line in measured.splitlines() if line in self.stp_lines]
        return defaults + "".join(line + "\n" for line in retained)

    def check_query(self, command):
        if command in ("show mlag peer", "show mlag ports"):
            host = "exosvm" if self.mlag else "x440"
            return reading(host + "__" + command.replace(" ", "-") + ".txt")
        if command == "show elrp":
            return reading("before__elrp.out")
        if command == "show sharing":
            return reading("before__lag.out")
        if command == "show ports 10 configuration no-refresh":
            text = reading(self.phase + "__link.out")
            return text.split("Flow Cntrl:")[0] if self.truncated else text
        if command == "show ports 10 information detail":
            detail = reading(self.phase + "__info.out")
            return detail.replace("Link State:\tReady", "Link State:\tActive") if self.active_stp_port else detail
        if command.startswith("show stpd g44stp"):
            if command.endswith("detail"):
                suffix = "stp-detail"
            else:
                suffix = "stp-port" if "ports" in command else "stp"
            changed = any(" priority " in line for line in self.stp_lines) if suffix == "stp" else self.stp_phase == "set"
            return reading(("stp-port-set" if changed else "stp") + "__" + suffix + ".out")
        return super().check_query(command)

    def answer(self, command):
        if command == "show configuration stp":
            return self.stp_module()
        if command == "show configuration vlan":
            return reading(self.phase + "__vsc.out")
        return super().answer(command)

    def _command(self, words, automatic):
        command = shlex.join(words)
        transitions = {
            ("before", "configure ports 10 auto off speed 100 duplex full"): "forced",
            ("forced", "configure ports 10 auto on"): "before",
            ("forced", "enable jumbo-frame ports 10"): "jumbo",
            ("jumbo", "disable jumbo-frame ports 10"): "forced",
        }
        phase = transitions.get((self.phase, command))
        if phase:
            self.phase, self.unsaved = phase, True
            return True
        if self.stp and words[:3] in (["configure", "stpd", "g44stp"], ["unconfigure", "stpd", "g44stp"]):
            return self.apply_stp(words, command)
        return super()._command(words, automatic)


    def apply_stp(self, words, command):
        measured = reading("stp-port-set__ssc.out").splitlines()
        if words[3] == "priority":
            for line in measured:
                if line.startswith("configure stpd g44stp priority "):
                    if words[4] == "32768":
                        self.stp_lines.remove(line)
                    else:
                        assert words[4] == line.split()[4]
                        self.stp_lines.append(line)
                    self.unsaved = True
                    return True
        inverse = {
            "configure stpd g44stp ports edge-safeguard disable 10": (
                "configure stpd g44stp ports edge-safeguard enable 10",
                "configure stpd g44stp ports bpdu-restrict enable 10"),
            "unconfigure stpd g44stp ports link-type 10": ("configure stpd g44stp ports link-type edge 10",),
            "configure stpd g44stp ports cost auto 10": ("configure stpd g44stp ports cost 30000 10",),
        }
        if command in inverse:
            for line in inverse[command]:
                self.stp_lines.remove(line)
            self.stp_phase = "default"
        elif command in measured and words[3] == "ports":
            self.stp_lines.append(command)
            self.stp_phase = "set"
        else:
            return False
        self.unsaved = True
        return True


def test_port_link_apply_undo(monkeypatch, tmp_path):
    switch = Links()
    setup(monkeypatch, tmp_path, switch)
    before = switch.snapshot()
    request = args("port-link", {"autonegotiation": "disabled", "speed": "100", "duplex": "full", "jumbo-frame": "enabled"})
    rejected = call("admin_apply", request)
    assert rejected["reason_codes"] == ["plan_changed"] and not switch.applied_blocks
    preview, applied = preview_apply(switch, request)
    assert preview["commands"] == ["configure ports 10 auto off speed 100 duplex full", "enable jumbo-frame ports 10"]
    assert switch.phase == "jumbo"
    undo(switch, applied)
    assert switch.snapshot() == before


def test_incomplete_readback_refuses_before_write(monkeypatch, tmp_path):
    switch = Links()
    switch.truncated = True
    setup(monkeypatch, tmp_path, switch)
    result = call("admin_preview", args("port-link", {"jumbo-frame": "enabled"}))
    assert result["reason_codes"] == ["port_usage_unreadable"], result
    assert not switch.applied_blocks


def test_switch_pair_binding_protects_the_underlying_port(monkeypatch, tmp_path):
    switch = Links()
    switch.mlag = True
    setup(monkeypatch, tmp_path, switch)
    result = call("admin_preview", args("port-link", {"jumbo-frame": "enabled"}, key="5"))
    assert result["reason_codes"] == ["exos_link_scope"], result
    assert not switch.applied_blocks


@pytest.mark.parametrize("name", ["exosvm", "exosvm-peer"])
def test_switch_pair_mlag_show_answers_use_the_real_id_and_port(name):
    bindings = exos_g44.bindings_readback(reading(name + "__show-mlag-ports.txt"))
    peers = exos_g44.peers_readback(reading(name + "__show-mlag-peer.txt"))
    assert bindings["5"]["mlag-id"] == "104"
    _attrs, status, vlans, count = peers[bindings["5"]["peer"]]
    assert status == "Up"
    assert len(vlans) == 2
    assert count == 1


def test_disabled_stp_domain_preserves_configured_edge_type():
    snapshot = exos.load("# Module vlan configuration.\n" + reading("stp-port-set__ssc.out"), "33.6.1.14")
    attrs = snapshot.entries("stpd-port")["g44stp:10"].attributes
    assert exos_g44.stp_port_readback(reading("stp-port-set__stp-port.out"),
                                     reading("stp-port-set__stp-detail.out"), "g44stp:10", attrs) == attrs
    assert exos_g44.stpd_readback(reading("stp-port-set__stp.out"), "g44stp") == {"priority": "28672"}


def test_sharing_does_not_change_ports_with_unrestorable_vm_scheduler():
    body = reading("before__vsc.out") + "# Module vsm configuration.\n"
    body += "configure qosscheduler strict-priority ports 11\n"
    request = parse_request(
        b'{"device":"sw","table":"sharing","key":"10","op":"create","changes":{"members":["10","11"]},'
        b'"reason":"isolation","user_request":"lab","request_id":"switch-aggregation-qos-test"}')
    with pytest.raises(exos_g44.Rejected, match="discard a configured QoS scheduler"):
        engine.build_plan("exos", body.encode(), request, firmware="33.6.1.14", ports=["10","11"])


@pytest.mark.parametrize(("table", "key", "changes"), [
    ("stpd", "g44stp", {"priority": 28672}),
    ("stpd-port", "g44stp:10", {"link-type": "edge", "cost": 30000,
                                 "edge-safeguard": "enabled", "bpdu-restrict": "enabled"}),
])
def test_stp_uses_captured_preview_apply_readback_and_undo(monkeypatch, tmp_path, table, key, changes):
    switch = Links()
    switch.stp = True
    setup(monkeypatch, tmp_path, switch)
    before = switch.snapshot()
    _preview, applied = preview_apply(switch, args(table, changes, key))
    assert switch.stp_lines
    undo(switch, applied)
    assert switch.snapshot() == before


def test_stp_priority_with_active_port_outside_management(monkeypatch, tmp_path):
    switch = Links()
    switch.stp = switch.active_stp_port = True
    setup(monkeypatch, tmp_path, switch)
    before = switch.snapshot()
    preview, applied = preview_apply(switch, args("stpd", {"priority": 28672}, "g44stp"))
    assert preview["commands"] == ["configure stpd g44stp priority 28672"]
    undo(switch, applied)
    assert switch.snapshot() == before


def test_stp_priority_protects_management_domain(monkeypatch, tmp_path):
    switch = Links()
    switch.stp = switch.active_stp_port = True
    runtime = setup(monkeypatch, tmp_path, switch)
    audit_policy(runtime, switch, management_vlans=["g44probe"])
    result = call("admin_preview", args("stpd", {"priority": 28672}, "g44stp"))
    assert result["reason_codes"] == ["port_management_vlan"], result
    assert not switch.applied_blocks


def test_stp_priority_protects_ssh_path_in_default_domain(monkeypatch, tmp_path):
    class DefaultStp(Links):
        def check_query(self, command):
            if command == "show stpd s0":
                return reading("stp__stp.out").replace("g44stp", "s0", 1).replace("g44probe", "Default", 1)
            return super().check_query(command)

    switch = DefaultStp()
    setup(monkeypatch, tmp_path, switch)
    result = call("admin_preview", args("stpd", {"priority": 28672}, "s0"))
    assert result["reason_codes"] == ["port_management_interface"], result
    assert not switch.applied_blocks


def test_untested_firmware_warns_without_blocking_preview(monkeypatch, tmp_path):
    switch = Links()
    switch.firmware = "33.8.0"
    setup(monkeypatch, tmp_path, switch, firmware=switch.firmware)
    preview = call("admin_preview", args("port-link", {"jumbo-frame": "enabled"}))
    assert preview["result"] == "ready", preview
    assert preview["firmware_support"]["status"] == "untested"
    assert not switch.applied_blocks


class SharingLinks(Links):
    """Model the X440's measured loss and explicit restoration of Default membership."""

    def __init__(self):
        super().__init__()
        self.sharing = "absent"
        self.native8 = True
        self.tagged10 = False
        self.algorithm = None

    def sharing_reading(self, name):
        content = reading(f"x440-sharing-{self.sharing}__{name}.out")
        return content.replace("L3_L4", self.algorithm) if self.algorithm is not None else content

    def snapshot(self):
        base = super().snapshot()
        membership = "5-16" if self.native8 else "5-7,9-16"
        vlan = f"configure vlan Default delete ports all\nconfigure vlan Default add ports {membership} untagged\n"
        if self.tagged10:
            vlan += 'create vlan "g44data"\nconfigure vlan g44data tag 3945\nconfigure vlan g44data add ports 10 tagged\n'
        config = self.sharing_reading("config").split("\n", 1)[1]
        return base.replace("# Module ems configuration.", vlan + config + "# Module ems configuration.")

    def answer(self, command):
        if command == "show configuration vlan":
            return self.sharing_reading("config")
        return super().answer(command)

    def check_query(self, command):
        if command == "show sharing":
            return self.sharing_reading("cli")
        if command == "show ports 8 information detail":
            # The row retains the real measured Ready state and grammar.
            return reading("x440__show-ports-10-information-detail.txt").replace("Port:\t10", "Port:\t8", 1)
        return super().check_query(command)

    def _command(self, words, automatic):
        command = shlex.join(words)
        if self.tagged10 and words[:5] == ["configure", "sharing", "10", "algorithm", "address-based"]:
            self.algorithm, self.unsaved = words[5], True
            return True
        transitions = {
            ("absent", "enable sharing 10 grouping 10 lacp"): "one",
            ("one", "configure sharing 10 add ports 8"): "one",
            ("one", "configure sharing 10 algorithm address-based L3_L4"): "two",
            ("two", "configure sharing 10 delete ports 8"): "two",
            ("two", "configure sharing 10 algorithm address-based L2"): "one",
            ("one", "configure vlan Default add ports 8 untagged"): "one",
            ("one", "disable sharing 10"): "absent",
        }
        state = transitions.get((self.sharing, command))
        if state is None:
            return super()._command(words, automatic)
        if command == "configure sharing 10 add ports 8":
            self.native8 = False
        elif command == "configure vlan Default add ports 8 untagged":
            self.native8 = True
        self.sharing, self.unsaved = state, True
        return True


def test_x440_sharing_members_and_vlan_restore_over_public_admin(monkeypatch, tmp_path):
    switch = SharingLinks()
    setup(monkeypatch, tmp_path, switch)
    baseline = switch.snapshot()
    create = args("sharing", {"members": ["10"]}, op="create", request_id="switch-aggregation-sharing-create")
    _preview, created = preview_apply(switch, create)
    first = switch.snapshot()
    update = args("sharing", {"members": ["8", "10"], "algorithm": "L3_L4"}, request_id="switch-aggregation-sharing-update")
    preview, updated = preview_apply(switch, update)
    assert preview["commands"] == ["configure sharing 10 add ports 8",
                                    "configure sharing 10 algorithm address-based L3_L4"]
    assert switch.sharing == "two" and not switch.native8
    undo(switch, updated)
    assert switch.snapshot() == first and switch.native8
    undo(switch, created)
    assert switch.snapshot() == baseline


def test_sharing_algorithm_on_tagged_trunk_over_public_admin(monkeypatch, tmp_path):
    switch = SharingLinks()
    switch.sharing, switch.native8, switch.tagged10 = "two", False, True
    setup(monkeypatch, tmp_path, switch)
    before = switch.snapshot()
    preview, applied = preview_apply(switch, args("sharing", {"algorithm": "L2"}))
    assert preview["commands"] == ["configure sharing 10 algorithm address-based L2"]
    assert "configure vlan g44data add ports 10 tagged" in switch.snapshot()
    undo(switch, applied)
    assert switch.snapshot() == before


def test_sharing_algorithm_protects_tagged_management_vlan(monkeypatch, tmp_path):
    switch = SharingLinks()
    switch.sharing, switch.native8, switch.tagged10 = "two", False, True
    runtime = setup(monkeypatch, tmp_path, switch)
    audit_policy(runtime, switch, management_vlans=["g44data"])
    result = call("admin_preview", args("sharing", {"algorithm": "L2"}))
    assert result["reason_codes"] == ["port_management_vlan"], result
    assert not switch.applied_blocks


def test_sharing_algorithm_protects_ssh_path(monkeypatch, tmp_path):
    switch = SharingLinks()
    switch.sharing, switch.native8, switch.tagged10 = "two", False, True
    switch.ssh_client_port = "10"
    setup(monkeypatch, tmp_path, switch)
    result = call("admin_preview", args("sharing", {"algorithm": "L2"}))
    assert result["reason_codes"] == ["port_management_interface"], result
    assert not switch.applied_blocks


def test_missing_lacp_group_row_is_incomplete():
    fixture = reading("x440-sharing-two__cli.out")
    truncated = "\n".join(line for line in fixture.splitlines() if not line.strip().startswith(("10", "L3_L4")))
    with pytest.raises(exos_g44.Rejected) as caught:
        exos_g44.sharing_readback(truncated, "10", {"algorithm": "L3_L4"})
    assert caught.value.reason_codes == ["port_usage_unreadable"]


def test_lacp_readback_reports_the_operational_algorithm():
    fixture = reading("x440-sharing-two__cli.out")
    assert exos_g44.sharing_readback(fixture, "10", {"algorithm": "L2"}) == {
        "members": "10 8", "algorithm": "L3_L4",
    }


def test_disabled_elrp_refuses_periodic_session_over_public_admin(monkeypatch, tmp_path):
    switch = Links()
    switch.stp = True
    setup(monkeypatch, tmp_path, switch)
    result = call("admin_preview", args("elrp", {"ports": ["10"], "interval": 1}, "g44probe", op="create"))
    assert result["reason_codes"] == ["exos_link_scope"], result
    assert "client must already be enabled" in result["reasons"][0]
    assert not switch.applied_blocks


class ElrpLinks(Links):
    def __init__(self, reported_session, *, milliseconds=False):
        super().__init__()
        self.vlans["V10"] = {"tag": "3945"}
        self.session = ""
        self.reported_session = reported_session
        self.milliseconds = milliseconds

    def snapshot(self):
        base = super().snapshot().replace("# Module ems configuration.",
                                           "configure vlan V10 add ports 10 tagged\n# Module ems configuration.")
        return base + "enable elrp-client\n" + self.session

    def answer(self, command):
        if command == "show configuration elrp":
            return "# Module elrp configuration.\nenable elrp-client\n" + self.session
        return super().answer(command)

    def check_query(self, command):
        if command == "show elrp":
            if not self.session:
                return reading("before__elrp.out").replace("Disabled", "Enabled", 1)
            measured = (HELPER_EXOS / "x440g2-12p-10g4_33.7.1.6_2/elrp.txt").read_text()
            return re.sub(r"^CLI +V10 +.*", self.reported_session, measured, flags=re.M)
        return super().check_query(command)

    def _command(self, words, automatic):
        if words[:4] == ["configure", "elrp-client", "periodic", "V10"]:
            if self.milliseconds:
                # The exosvm VM stores the CLI's seconds as milliseconds.
                words = [*words[:3], "vlan", *words[3:7], str(int(words[7]) * 1000), "milliseconds", *words[9:]]
            self.session = shlex.join(words) + "\n"
        elif words == ["unconfigure", "elrp-client", "V10"]:
            self.session = ""
        else:
            return super()._command(words, automatic)
        self.unsaved = True
        return True


@pytest.mark.parametrize("row", [
    "CLI    V10           1-16               1.000     0 Yes     22666846       0 LTI    Perm    ",
    "CLI    V10           10                 5.000     0 Yes            1       0 LT     -",
], ids=["different-ports-and-interval", "different-action"])
def test_elrp_independent_readback_mismatch_reverts(monkeypatch, tmp_path, row):
    switch = ElrpLinks(row)
    setup(monkeypatch, tmp_path, switch)
    before = switch.snapshot()
    request = args("elrp", {"ports": ["10"], "interval": 5}, "V10", op="create")
    preview = call("admin_preview", request)
    assert preview["result"] == "ready", preview
    result = call("admin_apply", dict(request, expected_plan_sha256=preview["plan_sha256"]))
    assert result["result"] == "reverted" and result["reason"] == "check identity mismatch", result
    assert switch.snapshot() == before


def test_elrp_independent_readback_matches_and_undoes(monkeypatch, tmp_path):
    switch = ElrpLinks("CLI    V10           10                 5.000     0 Yes            1       0 L      -",
                       milliseconds=True)
    setup(monkeypatch, tmp_path, switch)
    before = switch.snapshot()
    _, applied = preview_apply(switch, args("elrp", {"ports": ["10"], "interval": 5}, "V10", op="create"))
    undo(switch, applied)
    assert switch.snapshot() == before


class SfpLinks(Links):
    def snapshot(self):
        return super().snapshot().replace("# Module ems configuration.",
                                          "configure ports 13 auto off speed 10000 duplex full\n# Module ems configuration.")

    def check_query(self, command):
        if command == "show ports 13 configuration no-refresh":
            measured = (HELPER_EXOS / "x440g2-12p-10g4_33.7.1.6/ports_configuration.txt").read_text()
            header, rows, footer = re.split(r"^(?=={10,})", measured, flags=re.M)
            return header + "\n".join([rows.splitlines()[0], next(
                line for line in rows.splitlines() if line.startswith("13 "))]) + "\n" + footer
        if command == "show ports 13 information detail":
            return reading("x440__port-13-info.out")
        return super().check_query(command)


def test_sfp_port_link_with_blank_actual_autoneg(monkeypatch, tmp_path):
    switch = SfpLinks()
    setup(monkeypatch, tmp_path, switch)
    result = call("admin_preview", args("port-link", {"jumbo-frame": "enabled"}, "13"))
    assert result["result"] == "ready", result
    assert result["commands"] == ["enable jumbo-frame ports 13"]
    assert not switch.applied_blocks


def test_global_jumbo_plan_documents_scope_and_exact_inverse():
    # The example value and default come from the EXOS CLI reference.
    body = reading("before__vsc.out") + "# Module vsm configuration.\n"
    request = parse_request(
        b'{"device":"sw","table":"jumbo-frame-size","key":"global","op":"update","changes":{"size":5500},'
        b'"reason":"isolated validation","user_request":"lab","request_id":"switch-aggregation-mtu-test"}')
    plan = engine.build_plan("exos", body.encode(), request, firmware="33.6.1.14", ports=["10"])
    assert "switch-wide frame size" in " ".join(plan["prechecks"])
    assert plan["commands"] == ["configure jumbo-frame-size 5500"]
    assert plan["inverse"] == ["configure jumbo-frame-size 9216"]
    updated = body.replace("# Module vsm", "configure jumbo-frame-size 5500\n# Module vsm")
    assert engine.verify(plan, updated.encode(), expect="after")["result"] == "match"
    assert engine.verify(plan, body.encode(), expect="before")["result"] == "match"


class PeerLinks(Links):
    """Project the real SWITCH-PAIR peer output onto a test peer and bindings."""

    def __init__(self):
        super().__init__()
        self.peer = None
        self.binding = False
        self.checkpoint = "Down"
        self.reported_bindings = None

    def snapshot(self):
        base = super().snapshot()
        isc = ('create vlan "host02"\nconfigure vlan host02 tag 3944\n'
               "configure vlan host02 add ports 10 untagged\n"
               "configure vlan host02 ipaddress 192.0.2.1 255.255.255.252\n")
        base = base.replace("# Module ems configuration.", isc + "# Module ems configuration.")
        if self.peer is not None:
            lines = 'create mlag peer "host04"\n'
            if self.peer:
                lines += f'configure mlag peer "host04" ipaddress {self.peer} vr VR-Default\n'
            if self.binding:
                lines += 'enable mlag port 8 peer "host04" id 104\n'
            base = base.replace("# Module vsm configuration.\n", "# Module vsm configuration.\n" + lines)
        return base

    def check_query(self, command):
        if command == "show mlag peer" and self.peer:
            text = reading("exosvm__show-mlag-peer.txt").split("Alternate path information:")[0]
            count = int(self.binding) if self.reported_bindings is None else self.reported_bindings
            return text.replace("Checkpoint Status : Up", "Checkpoint Status : " + self.checkpoint).replace(
                "MLAG ports        : 1", "MLAG ports        : %d" % count)
        if command == "show mlag ports" and self.binding:
            text = reading("exosvm__show-mlag-ports.txt")
            return text.replace("104     5", "104     8", 1)
        if command == "show ports 8 information detail":
            return reading("x440__show-ports-10-information-detail.txt").replace("Port:\t10", "Port:\t8", 1)
        return super().check_query(command)

    def _command(self, words, automatic):
        command = shlex.join(words)
        if command == "create mlag peer host04" and self.peer is None:
            self.peer = ""
        elif command == "configure mlag peer host04 ipaddress 192.0.2.2 vr VR-Default" and self.peer == "":
            self.peer = "192.0.2.2"
        elif command == "delete mlag peer host04" and self.peer is not None:
            self.peer = None
        elif command == "enable mlag port 8 peer host04 id 104" and self.peer and not self.binding:
            self.binding = True
        elif command == "disable mlag port 8" and self.binding:
            self.binding = False
        else:
            return super()._command(words, automatic)
        self.unsaved = True
        return True


def test_mlag_peer_create_and_undo_without_bindings(monkeypatch, tmp_path):
    switch = PeerLinks()
    switch.checkpoint = "Up"
    setup(monkeypatch, tmp_path, switch).simulate_unmeasured_profiles = True
    before = switch.snapshot()
    body = args("mlag-peer", {"peer-ip": "192.0.2.2"}, "host04", op="create")
    preview, applied = preview_apply(switch, body)
    assert preview["commands"] == ["create mlag peer host04",
                                    "configure mlag peer host04 ipaddress 192.0.2.2 vr VR-Default"]
    undo(switch, applied)
    assert switch.snapshot() == before


def test_mlag_peer_undo_refuses_operational_binding_count(monkeypatch, tmp_path):
    switch = PeerLinks()
    switch.checkpoint = "Up"
    setup(monkeypatch, tmp_path, switch).simulate_unmeasured_profiles = True
    request = args("mlag-peer", {"peer-ip": "192.0.2.2"}, "host04", op="create")
    _, applied = preview_apply(switch, request)
    switch.reported_bindings = 1
    result = call("admin_undo_preview", {"change_id": applied["change_id"], "reason": "restore baseline"})
    assert result["reason_codes"] == ["exos_link_scope"], result
    assert "operational port bindings" in result["reasons"][0]


def test_mlag_binding_create_and_undo_preserves_the_peer(monkeypatch, tmp_path):
    switch = PeerLinks()
    switch.peer = "192.0.2.2"
    setup(monkeypatch, tmp_path, switch).simulate_unmeasured_profiles = True
    before = switch.snapshot()
    body = args("mlag-port", {"peer": "host04", "mlag-id": 104}, "8", op="create")
    preview, applied = preview_apply(switch, body)
    assert preview["commands"] == ["enable mlag port 8 peer host04 id 104"]
    assert switch.binding
    undo(switch, applied)
    assert switch.snapshot() == before
