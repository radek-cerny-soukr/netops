"""SWITCH-ACCESS-CONTROL changes through Admin preview, apply and undo with measured EXOS CLI responses."""

from pathlib import Path

import pytest

from conftest import request_bytes
from fake_exos import FakeExos
from netops_admin import engine, execute, exos, prediction
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.request import parse_request
from test_execute_exos import make_runtime

FIXTURES = Path(__file__).parent / "fixtures" / "exos_switch_access_control"
VLAN = "netops-switch-access-control"
FIRMWARE = "33.6.1.14"
RELAY = {"server-ip": "192.0.2.254"}
POOL = {"range-start": "192.0.2.30", "range-end": "192.0.2.49", "lease-seconds": "3600",
        "default-gateway": "192.0.2.1", "primary-dns": "192.0.2.2", "secondary-dns": "192.0.2.3", "ports": ["10"]}
RELAY_READ = f"show bootprelay configuration ipv4 vlan {VLAN}"
POOL_READ = f"show vlan {VLAN} dhcp-config"
SERVER_READ = f"show dhcp-server vlan {VLAN}"
VLAN_READ = f"show vlan {VLAN}"


def fixture(name):
    return (FIXTURES / (name + ".out")).read_text()


def request(table, changes, **extra):
    return parse_request(request_bytes(table=table, key=VLAN, op="update", changes=changes, **extra))


class DHCPDevice(FakeExos):
    """Only the transport and switch mutation state are simulated. Readbacks come from the captured states."""

    def __init__(self):
        super().__init__()
        self.firmware = FIRMWARE
        self.dhcp_lines = set()
        self.answers = {}
        self.read_commands = []
        self.written = False

    def snapshot(self):
        text = super().snapshot()
        settings = "\n".join(sorted(self.dhcp_lines))
        return text.replace("# Module ems configuration.", fixture("base-config") + "# Module ems configuration.").replace(
            "# Module snmpMaster configuration.", settings + "\n# Module snmpMaster configuration."
        )

    def _command(self, words, automatic):
        if VLAN not in words or not ({"dhcp", "bootprelay"} & set(words) or any(w.startswith("dhcp-") for w in words)):
            return super()._command(words, automatic)
        if words[:2] == ["unconfigure", "vlan"] and words[-1] == "dhcp":
            self.dhcp_lines = {line for line in self.dhcp_lines if "bootprelay" in line}
        elif words[:2] == ["disable", "bootprelay"] or words[:2] == ["disable", "dhcp"]:
            self.dhcp_lines.discard("enable " + " ".join(words[1:]))
        elif words[:2] == ["configure", "bootprelay"] and words[4] == "delete":
            self.dhcp_lines.discard(" ".join(words[:4] + ["add", words[5]]))
        else:
            normalized = " ".join(words).replace(" dns-server primary ", " dns-server ")
            self.dhcp_lines.add(normalized)
        self.unsaved = True
        self.written = True
        return True

    def check_query_status(self, command):
        self.read_commands.append(command)
        if command in self.answers:
            result = self.answers[command]
            if isinstance(result, Exception):
                raise result
            return result
        if command == VLAN_READ:
            return 250, fixture("base-vlan")
        if command == RELAY_READ:
            enabled = any(line.startswith("enable bootprelay") for line in self.dhcp_lines)
            return 0, fixture("relay-on-relay" if enabled else ("relay-undo-relay" if self.written else "base-relay"))
        has_pool = any("dhcp-address-range" in line for line in self.dhcp_lines)
        if command == POOL_READ:
            return 0, fixture("pool-on-pool" if has_pool else ("pool-undo-pool" if self.written else "base-pool"))
        if command == SERVER_READ:
            return 0, fixture("pool-on-server" if has_pool else "base-server")
        raise AssertionError("unexpected read from check account: " + command)


@pytest.mark.parametrize(("table", "changes", "captured"), [
    (exos.DHCP_RELAY, RELAY, "relay-on-config"),
    (exos.DHCP_SERVER, POOL, "pool-on-config"),
])
def test_preview_apply_undo(tmp_path, table, changes, captured):
    switch = DHCPDevice()
    runtime = make_runtime(tmp_path, switch, firmware=FIRMWARE)
    req = request(table, changes)
    original = switch.snapshot()
    preview = execute.preview(runtime, "sw", req)
    assert preview["result"] == "ready", preview
    assert preview["predicted"]["before"] == {}
    assert switch.applied_blocks == []
    with pytest.raises(Rejected, match="approved preview"):
        execute.apply(runtime, "sw", req)
    assert switch.applied_blocks == []
    applied = execute.apply(runtime, "sw", req, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", applied
    assert {"postcheck_passed", "check_identity_passed"} <= {step["step"] for step in applied["steps"]}
    measured = exos.load(fixture(captured), FIRMWARE).entries(table)[VLAN].attributes
    assert preview["predicted"]["after"] == measured
    predicted = prediction.snapshot_after(original, applied["plan"])
    assert engine.verify(applied["plan"], predicted.encode())["result"] == "match"
    if table == exos.DHCP_RELAY:
        conflicting = request(exos.DHCP_SERVER, POOL, request_id="conflicting", endpoint_impact=VLAN)
        refused = execute.preview(runtime, "sw", conflicting)
        assert refused["reason_codes"] == ["exos_dhcp_conflict"], refused
        no_ack = request(table, {"server-ip": "192.0.2.253"}, request_id="existing")
        assert execute.preview(runtime, "sw", no_ack)["reason_codes"] == ["endpoint_impact_required"]
    return_preview = execute.preview_undo(runtime, applied["change_id"], "restore SWITCH-ACCESS-CONTROL", issue=True)
    assert return_preview["result"] == "ready", return_preview
    undone = execute.undo(runtime, applied["change_id"], "restore SWITCH-ACCESS-CONTROL",
                          expected_plan_sha256=return_preview["plan_sha256"])
    assert undone["result"] == "confirmed", undone
    assert switch.snapshot() == original
    assert not switch.profiles and not switch.timers and not switch.unsaved
    assert {RELAY_READ, POOL_READ, VLAN_READ, SERVER_READ} <= set(switch.read_commands)


@pytest.mark.parametrize(("command", "answer", "table", "changes", "code"), [
    (RELAY_READ, (0, ""), exos.DHCP_RELAY, RELAY, "exos_dhcp_readback_unreadable"),
    (RELAY_READ, (0, fixture("relay-on-relay").split('VLAN "netops-switch-access-control":')[0]), exos.DHCP_RELAY, RELAY,
     "exos_dhcp_readback_unreadable"),
    (POOL_READ, (0, fixture("pool-on-pool").split("    Ports DHCP Enabled")[0]), exos.DHCP_SERVER, POOL,
     "exos_dhcp_readback_unreadable"),
    (POOL_READ, (250, "%% Invalid input detected at '^' marker.\n"), exos.DHCP_SERVER, POOL,
     "exos_dhcp_unsupported"),
    (POOL_READ, AccessError("connection timed out"), exos.DHCP_SERVER, POOL, "exos_dhcp_read_timeout"),
    (VLAN_READ, (0, fixture("base-vlan").replace("active ports=0", "active ports=1")), exos.DHCP_SERVER, POOL,
     "exos_dhcp_conflict"),
])
def test_refusals_happen_before_any_write(tmp_path, command, answer, table, changes, code):
    switch = DHCPDevice()
    switch.answers[command] = answer
    runtime = make_runtime(tmp_path, switch, firmware=FIRMWARE)
    refused = execute.preview(runtime, "sw", request(table, changes, endpoint_impact=VLAN))
    assert refused["result"] == "rejected"
    assert refused["reason_codes"] == [code], refused
    assert not switch.applied_blocks


def test_hidden_relay_and_untested_firmware(tmp_path):
    switch = DHCPDevice()
    switch.firmware = "33.8.0"
    runtime = make_runtime(tmp_path, switch, firmware=switch.firmware)
    preview = execute.preview(runtime, "sw", request(exos.DHCP_RELAY, RELAY))
    assert preview["result"] == "ready", preview
    assert preview["firmware_support"]["status"] == "untested"
    staged = exos.load(fixture("relay-target-config"), FIRMWARE)
    switch.dhcp_lines.update(command.text for command in staged.commands if command.module == exos.DHCP_MODULE)
    refused = execute.preview(runtime, "sw", request(exos.DHCP_SERVER, POOL, endpoint_impact=VLAN))
    assert refused["reason_codes"] == ["exos_dhcp_conflict"], refused
    assert not switch.applied_blocks


def test_lease_edit_does_not_reset_or_reconfigure_existing_pool():
    config = fixture("pool-on-config").encode()
    req = request(exos.DHCP_SERVER, {"lease-seconds": 7200}, endpoint_impact=VLAN)
    plan = engine.build_plan("exos", config, req, firmware=FIRMWARE)
    assert plan["commands"] == [f"configure vlan {VLAN} dhcp-lease-timer 7200"]
    assert plan["inverse"] == [f"configure vlan {VLAN} dhcp-lease-timer 3600"]
    req = request(exos.DHCP_SERVER, {"lease-seconds": None}, endpoint_impact=VLAN)
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", config, req, firmware=FIRMWARE)
    assert caught.value.reason_codes == ["exos_dhcp_inverse_unsupported"]


def test_vr_wide_targets_cannot_be_inherited_by_a_new_relay(tmp_path):
    switch = DHCPDevice()
    switch.dhcp_lines.add("configure bootprelay add 192.0.2.253")
    runtime = make_runtime(tmp_path, switch, firmware=FIRMWARE)
    preview = execute.preview(runtime, "sw", request(exos.DHCP_RELAY, RELAY))
    assert preview["reason_codes"] == ["exos_dhcp_conflict"], preview
    assert not switch.applied_blocks


def test_default_lease_cannot_be_replaced_in_a_preexisting_pool(tmp_path):
    switch = DHCPDevice()
    switch.dhcp_lines.add("configure vlan netops-switch-access-control dhcp-address-range 192.0.2.30 - 192.0.2.49")
    switch.answers[POOL_READ] = (0, fixture("range-only-pool"))
    runtime = make_runtime(tmp_path, switch, firmware=FIRMWARE)
    option = request(exos.DHCP_SERVER, {"primary-dns": "192.0.2.2"}, endpoint_impact=VLAN)
    preview = execute.preview(runtime, "sw", option)
    assert preview["result"] == "ready", preview
    assert preview["predicted"]["before"] == {"range-start": "192.0.2.30", "range-end": "192.0.2.49"}
    lease = request(exos.DHCP_SERVER, {"lease-seconds": 3600}, endpoint_impact=VLAN)
    assert execute.preview(runtime, "sw", lease)["reason_codes"] == ["exos_dhcp_inverse_unsupported"]
    assert not switch.applied_blocks
