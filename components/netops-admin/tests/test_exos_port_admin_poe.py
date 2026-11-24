"""Port admin state and PoE cycle on ExtremeXOS (1.0.9 item 18).

Parser tests read the anonymised outputs measured on X435-8P-4S and X440-G2-12p-10G4 with 33.7.1.6-patch1-11
(fixtures/exos_port_poe); the execution tests run the fake switch, whose answers use the same measured layouts.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from enrollment_helpers import certify
from fake_exos import FIRMWARE, FakeExos, fixture

from netops_admin import engine, exec_exos, execute, exos, exos_poe, profiles, readiness
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.errors import BudgetExhausted, Rejected
from netops_admin.request import parse_request
from approved_apply import approved_apply, approved_cycle

GOLDEN = Path(__file__).parent / "golden" / "exos" / "33.7.1.6-patch1-11"
X435_CONFIGURATION = GOLDEN / "X435-8P-4S" / "show-configuration" / "X435-8P-4S__normal-redacted-secrets.conf"
INVENTORY = [str(number) for number in range(1, 17)]


def make_runtime(tmp_path, device, protected=None, limits=None, firmware=FIRMWARE, safeguard_seconds=180,
                 confirm_margin_seconds=45):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=None, notify=None, limits=dict(limits or DEFAULT_LIMITS),
        devices={"sw": Device(
            name="sw", platform="exos", address="192.0.2.2", port=22,
            host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw",
            check_credential="ro", firmware=firmware, safeguard_seconds=safeguard_seconds,
            confirm_margin_seconds=confirm_margin_seconds,
            protected=dict(protected or {}), legacy_ssh="rsa-sha1", accounts=("admin", "netops-rw"),
        )},
    )
    runtime = execute.Runtime(config, lambda _device: device, sleep=device.advance)
    runtime.monotonic = lambda: device.uptime
    return certify(runtime, device, "sw")


# a PoE cycle takes up to exos_poe.CYCLE_SECONDS (175 s) and needs the confirm margin (45 s) on top
POE_SAFEGUARD_SECONDS = 240


def poe_runtime(tmp_path, device, **options):
    options.setdefault("safeguard_seconds", POE_SAFEGUARD_SECONDS)
    return make_runtime(tmp_path, device, **options)


def port_request(key="10", state="disabled", request_id="req-admin-0001"):
    return parse_request(request_bytes(table="ports", op="update", key=key, changes={"admin-state": state},
                                       request_id=request_id))


def cycle_request(port="10", request_id="req-poe-0001"):
    return exos_poe.request("sw", port, "access point hangs", "restart PoE on port %s" % port, request_id)


def steps(record):
    return [step["step"] for step in record["steps"]]


def clean(device):
    return not device.profiles and not device.timers


def plain_blocks(device):
    return [block for block in device.applied_blocks if all(isinstance(step, str) for step in block)]


# ---- parsers on the measured outputs ------------------------------------------------------------------


@pytest.mark.parametrize(("name", "port"), [("x435__36-cfgvlan-dis.out", "8"), ("x440__36-cfgvlan-dis.out", "10")])
def test_disabled_port_is_read_from_show_configuration_vlan(name, port):
    snapshot = exos.Snapshot(fixture(name), FIRMWARE)
    assert snapshot.entries("ports")[port].attributes["admin-state"] == "disabled"
    enabled = exos.Snapshot(fixture("x435__44-cfgvlan-en.out"), FIRMWARE).entries("ports")
    assert "admin-state" not in enabled.get("8", exos.Entry("8")).attributes


def test_disabled_inline_power_is_read_from_module_poe():
    text = X435_CONFIGURATION.read_text(encoding="utf-8").replace(
        "# Module poe configuration.\n#\n", "# Module poe configuration.\n#\ndisable inline-power ports 8\n", 1)
    snapshot = exos.Snapshot(text, FIRMWARE)
    assert snapshot.entries("inline-power")["8"].attributes == {"admin-state": "disabled"}
    assert snapshot.entries("ports").get("8") is None
    plain = exos.Snapshot(X435_CONFIGURATION.read_text(encoding="utf-8"), FIRMWARE)
    assert plain.entries("inline-power") == {}
    assert snapshot.rest_digest("inline-power", "8") == plain.rest_digest("inline-power", "8")
    assert snapshot.rest_digest("inline-power", "7") != plain.rest_digest("inline-power", "7")


def test_disabled_port_lists_refuse_only_the_listed_ports():
    text = FakeExos().snapshot().replace("configure vlan DATA add ports 1-4 untagged",
                                         "configure vlan DATA add ports 1-4 untagged\ndisable port 5-6")
    for key in ("5", "6"):
        with pytest.raises(Rejected) as caught:
            engine.build_plan("exos", text.encode(), port_request(key=key, state="enabled"), firmware=FIRMWARE)
        assert "port list" in caught.value.reasons[0]
    plan = engine.build_plan("exos", text.encode(), port_request(key="10"), firmware=FIRMWARE)
    assert plan["commands"] == ["disable ports 10"]


def test_information_detail_gives_the_admin_state():
    assert exos.shown_port(fixture("x435__21-p-info-pre.out"), "8", admin_state=True) == {}
    assert exos.shown_port(fixture("x435__32-p-info-dis.out"), "8", admin_state=True) == {"admin-state": "disabled"}
    with pytest.raises(Rejected):
        exos.shown_port("Port:\t8\n\tVirtual-router:\tVR-Default\n", "8", admin_state=True)
    assert exos.shown_port("Port:\t8\n", "8") == {}


def test_port_configuration_gives_port_and_link_state():
    assert exos.port_configuration(fixture("x435__20-p-cfg-pre.out"), "8") == {"port_state": "enabled", "link_state": "ready"}
    assert exos.port_configuration(fixture("x435__31-p-cfg-dis.out"), "8") == {"port_state": "disabled", "link_state": "ready"}
    assert exos.port_configuration(fixture("x440__20-p-cfg-pre.out"), "10")["port_state"] == "enabled"
    assert exos.port_configuration(fixture("x435__47-disable-bad.out"), "99") is None


def test_lldp_and_fdb_name_the_ports_in_use():
    assert exos.lldp_ports(fixture("x435__03-lldp.out")) == {"1"}
    assert exos.lldp_ports(fixture("x440__03-lldp.out")) == {"1", "7"}
    assert exos.fdb_ports(fixture("x435__02-show-fdb.out")) == {"1"}
    assert exos.fdb_ports(fixture("x440__02-show-fdb.out")) == {"1", "3", "7", "9", "11"}


@pytest.mark.parametrize("damage", [
    lambda text: "\n".join(line for line in text.splitlines() if not line.endswith(" 11")) + "\n",
    lambda text: text.replace("Port / Virtual Port List", "Port"),
    lambda text: "",
])
def test_incomplete_fdb_is_refused(damage):
    with pytest.raises(Rejected) as caught:
        exos.fdb_ports(damage(fixture("x440__02-show-fdb.out")))
    assert caught.value.reason_codes == ["port_usage_unreadable"]


def test_unrecognised_lldp_is_refused():
    with pytest.raises(Rejected) as caught:
        exos.lldp_ports("%% Invalid input detected at '^' marker.\n")
    assert caught.value.reason_codes == ["port_usage_unreadable"]


def _cut_after(text: str, marker: str) -> str:
    """The answer up to and including the first line that starts with marker (a list cut off after it)."""
    lines = text.splitlines(keepends=True)
    index = next(number for number, line in enumerate(lines) if line.startswith(marker))
    return "".join(lines[:index + 1])


def _lldp_cuts(text: str) -> list:
    return [
        _cut_after(text, "Port "),                  # only the header
        _cut_after(text, "====="),                  # header and the opening separator
        _cut_after(text, "1 "),                     # a prefix with the first neighbor, no end
        _cut_after(text, "7 ") if "\n7 " in text else _cut_after(text, "1 ") + "\n",
        text.replace("NOTE: The Chassis ID and/or Port ID might be truncated to fit the screen.\n", ""),
        text.replace("NOTE:", "NOTE"),
        text + "8       00:00:5e:00:53:01  2                  120     5       late\n",
    ]


@pytest.mark.parametrize("name", ["x435__03-lldp.out", "x440__03-lldp.out"])
def test_cut_off_lldp_is_refused(name):
    for text in _lldp_cuts(fixture(name)):
        with pytest.raises(Rejected) as caught:
            exos.lldp_ports(text)
        assert caught.value.reason_codes == ["port_usage_unreadable"], text


@pytest.mark.parametrize("name", ["x435__03-lldp.out", "x440__03-lldp.out"])
def test_complete_empty_lldp_list_has_no_neighbor(name):
    text = fixture(name)
    lines = text.splitlines(keepends=True)
    opening, closing = [number for number, line in enumerate(lines) if line.startswith("=====")]
    empty = "".join(lines[:opening + 1] + lines[closing:])
    assert exos.lldp_ports(empty) == set()
    assert exos.lldp_ports(empty.replace("\n", "\r\n")) == set()


@pytest.mark.parametrize("name", ["x435__02-show-fdb.out", "x440__02-show-fdb.out"])
def test_cut_off_fdb_is_refused(name):
    text = fixture(name)
    lines = text.splitlines(keepends=True)
    total = next(number for number, line in enumerate(lines) if line.startswith("Total:"))
    last = next(number for number, line in enumerate(lines) if number > 1 and not line.strip()) - 1
    cuts = [
        _cut_after(text, "MAC "),                   # only the header
        _cut_after(text, "-----"),                  # header and separator
        "".join(lines[:3]),                         # a prefix with the first address, no Total
        "".join(lines[:total]),                     # all rows and the legend, no Total
        "".join(lines[:1] + lines[2:]),             # no separator under the header
        # the count matches the Total, but the last row stands after the Total line
        "".join(lines[:last] + lines[last + 1:total + 1] + [lines[last]]),
    ]
    for cut in cuts:
        with pytest.raises(Rejected) as caught:
            exos.fdb_ports(cut)
        assert caught.value.reason_codes == ["port_usage_unreadable"], cut


@pytest.mark.parametrize("name", ["x435__02-show-fdb.out", "x440__02-show-fdb.out"])
def test_complete_empty_fdb_has_no_learned_address(name):
    lines = fixture(name).splitlines(keepends=True)
    total = next(number for number, line in enumerate(lines) if line.startswith("Total:"))
    first_blank = next(number for number, line in enumerate(lines) if number > 1 and not line.strip())
    empty = "".join(lines[:2] + lines[first_blank:total])
    empty += "Total: 0 Static: 0  Perm: 0  Dyn: 0  Dropped: 0  Locked: 0  Locked with Timeout: 0\n"
    assert exos.fdb_ports(empty) == set()


def _cut_inside_vlan_module(text: str) -> str:
    lines = text.splitlines(keepends=True)
    start = next(number for number, line in enumerate(lines) if line.startswith("# Module vlan configuration."))
    following = next(number for number, line in enumerate(lines)
                     if number > start and line.startswith("# Module "))
    return "".join(lines[:following - 1])


def test_configuration_cut_off_inside_the_vlan_module_refuses_the_disable():
    device = FakeExos()
    text = device.snapshot()
    cut = _cut_inside_vlan_module(text)
    assert exos.vlan_module_closed(exos.Snapshot(text, FIRMWARE))
    assert not exos.vlan_module_closed(exos.Snapshot(cut, FIRMWARE))
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", cut.encode(), port_request(key="10"), firmware=FIRMWARE, ports=INVENTORY)
    assert caught.value.reason_codes == ["port_usage_unreadable"]
    plan = engine.build_plan("exos", text.encode(), port_request(key="10"), firmware=FIRMWARE, ports=INVENTORY)
    target = SimpleNamespace(firmware=FIRMWARE, audit_policy={})
    with pytest.raises(Rejected) as caught:
        exec_exos.plan_prechecks(device, target, plan, cut)
    assert caught.value.reason_codes == ["port_usage_unreadable"]
    assert exec_exos.plan_prechecks(device, target, plan, text) == []
    # enabling a port needs the VLAN membership too (verification: an enabled uplink or LAG member can loop)
    device.ports_disabled.add("10")
    enabled = device.snapshot()
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", _cut_inside_vlan_module(enabled).encode(), port_request(state="enabled"),
                          firmware=FIRMWARE, ports=INVENTORY)
    assert caught.value.reason_codes == ["port_usage_unreadable"]
    assert engine.build_plan("exos", enabled.encode(), port_request(state="enabled"),
                             firmware=FIRMWARE, ports=INVENTORY)["commands"] == ["enable ports 10"]


def test_golden_configurations_close_the_vlan_module():
    for path in GOLDEN.glob("*/show-configuration/*.conf"):
        assert exos.vlan_module_closed(exos.Snapshot(path.read_text(encoding="utf-8"), FIRMWARE)), path


def test_inline_power_rows_and_refusals():
    assert exos.poe_info(fixture("x435__23-ip-info-pre.out"), "8")["state"] == "searching"
    assert exos.poe_info(fixture("x435__51-ip-info-dis.out"), "8")["state"] == "searching"
    assert exos.poe_info(fixture("x440__11c-ip-info.out"), "10") == {
        "state": "searching", "class": "------", "power_watts": "0.000", "fault": "None"}
    for name, port in (("x435__27-ip-nopoe.out", "9"), ("x440__27-ip-nopoe.out", "13")):
        with pytest.raises(exos.NotInlinePower) as caught:
            exos.poe_info(fixture(name), port)
        assert caught.value.reason_codes == ["poe_not_capable"]
    with pytest.raises(Rejected) as caught:
        exos.poe_info(fixture("x435__11-ip-info-all.out"), "8")
    assert caught.value.reason_codes == ["poe_unsupported"]
    with pytest.raises(Rejected) as caught:
        exos.poe_info(fixture("x440__11c-ip-info.out"), "13")
    assert caught.value.reason_codes == ["poe_state_unreadable"]
    assert "not inline-power capable" in fixture("x435__60-ip-disable-nopoe.out")
    assert exos.cli_error("disable inline-power ports 9\n" + fixture("x435__60-ip-disable-nopoe.out"))


@pytest.mark.parametrize(("name", "port", "configured", "state"), [
    ("x435__25-ip-info-detail-pre.out", "8", "enabled", "searching"),
    ("x440__25-ip-info-detail-pre.out", "10", "enabled", "searching"),
    ("x435__52-ip-detail-dis.out", "8", "disabled", "disabled"),
    ("x440__52-ip-detail-dis.out", "10", "disabled", "disabled"),
    ("x435__59-ip-info-reset.out", "8", "enabled", "disabled"),
    # a UPM safeguard without persistent CLI mode: operation back on, configuration still disabled
    ("x440__84-ip-detail-now.out", "10", "disabled", "searching"),
])
def test_inline_power_detail(name, port, configured, state):
    detail = exos.poe_detail(fixture(name), port)
    assert (detail["configured"], detail["state"]) == (configured, state)


def test_inline_power_detail_of_another_port_is_refused():
    with pytest.raises(Rejected) as caught:
        exos.poe_detail(fixture("x435__25-ip-info-detail-pre.out"), "10")
    assert caught.value.reason_codes == ["poe_state_unreadable"]


# ---- plan, prediction and verification ----------------------------------------------------------------


def test_disable_and_enable_render_as_measured_and_invert():
    device = FakeExos()
    plan = engine.build_plan("exos", device.snapshot().encode(), port_request(), firmware=FIRMWARE, ports=INVENTORY)
    assert plan["commands"] == ["disable ports 10"] and plan["inverse"] == ["enable ports 10"]
    assert plan["predicted"] == {"before": {}, "after": {"admin-state": "disabled"}}
    assert exos.safeguard_script(plan["inverse"])[0] == "configure cli mode persistent"
    device.ports_disabled.add("10")
    assert engine.verify(plan, device.snapshot().encode())["result"] == "match"
    back = engine.build_plan("exos", device.snapshot().encode(), port_request(state="enabled"),
                             firmware=FIRMWARE, ports=INVENTORY)
    assert back["commands"] == ["enable ports 10"] and back["inverse"] == ["disable ports 10"]
    assert back["predicted"] == {"before": {"admin-state": "disabled"}, "after": {}}


def test_display_string_and_admin_state_share_the_port_object():
    device = FakeExos()
    device.ports_disabled.add("11")
    plan = engine.build_plan("exos", device.snapshot().encode(), parse_request(request_bytes(
        table="ports", op="update", key="11", changes={"display-string": "AP-hall"})), firmware=FIRMWARE)
    assert plan["predicted"] == {"before": {"display-string": "Zyxel-5p", "admin-state": "disabled"},
                                 "after": {"display-string": "AP-hall", "admin-state": "disabled"}}
    assert plan["commands"] == ["configure ports 11 display-string AP-hall"]


def test_enabling_an_enabled_port_changes_nothing():
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", FakeExos().snapshot().encode(), port_request(state="enabled"), firmware=FIRMWARE)
    assert caught.value.reasons == ["update changes nothing"]


def test_admin_state_on_untested_firmware_is_planned_with_a_warning():
    # STARTUP-1 (A5): other firmware is not refused, the plan warns
    text = FakeExos().snapshot().encode()
    plan = engine.build_plan("exos", text, port_request(), firmware="33.7.2")
    assert plan["commands"] == ["disable ports 10"] and plan["inverse"] == ["enable ports 10"]
    support = plan["firmware_support"]
    assert support["status"] == "untested" and support["device_version"] == "33.7.2"
    assert support["tested_versions"] == ["33.7.1.6", "33.6.1.14"] and "port admin state" in support["message"]
    assert plan["prechecks"][0].startswith("firmware 33.7.2 is not among the tested versions")
    tested_plan = engine.build_plan("exos", text, port_request(), firmware=FIRMWARE)
    assert tested_plan["firmware_support"]["status"] == "tested"
    # The measurement is claimed for the profile and its documented variants, not for the variant of this request
    assert tested_plan["prechecks"][0] == ("profile measured on firmware 33.7.1.6; the measurement covers the variants"
                                           " documented for this profile, not every variant of the request")
    assert not any("is measured for this profile" in check for check in tested_plan["prechecks"])
    # the display string keeps the tested scope of the ports profile, 33.6.1.14 included
    display = engine.build_plan("exos", text, parse_request(request_bytes(
        table="ports", op="update", key="10", changes={"display-string": "Cam-01"})), firmware="33.6.1.14")
    assert display["commands"] == ["configure ports 10 display-string Cam-01"]
    assert display["firmware_support"]["status"] == "tested"


def test_admin_state_on_untested_firmware_is_confirmed_with_the_warning(tmp_path):
    device = FakeExos()
    device.firmware = "33.7.2"
    runtime = make_runtime(tmp_path, device, firmware=device.firmware)
    preview = execute.preview(runtime, "sw", port_request())
    assert preview["result"] == "ready", preview
    assert preview["firmware_support"]["status"] == "untested"
    record = execute.apply(runtime, "sw", port_request(), expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert record["plan"]["firmware_support"] == preview["firmware_support"]
    assert device.ports_disabled == {"10"} and clean(device)
    back = execute.undo(runtime, record["change_id"], "port is needed again")
    assert back["result"] == "confirmed", back
    assert not device.ports_disabled and back["plan"]["firmware_support"]["status"] == "untested"


@pytest.mark.parametrize(("line", "code"), [
    ("configure vlan DATA add ports 5 tagged", "port_uplink"),
    ("enable sharing 5 grouping 5-6 algorithm address-based L2", "port_lag_member"),
])
def test_uplink_and_aggregated_ports_are_refused(line, code):
    text = FakeExos().snapshot().replace("configure vlan DATA add ports 1-4 untagged",
                                         "configure vlan DATA add ports 1-4 untagged\n" + line)
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", text.encode(), port_request(key="5"), firmware=FIRMWARE, ports=INVENTORY)
    assert caught.value.reason_codes == [code]


def test_management_vlan_of_the_audit_policy_is_refused():
    device = FakeExos()
    text = device.snapshot()
    plan = engine.build_plan("exos", text.encode(), port_request(key="10"), firmware=FIRMWARE, ports=INVENTORY)
    target = SimpleNamespace(firmware=FIRMWARE, audit_policy={"management_vlans": ["default"]})
    with pytest.raises(Rejected) as caught:
        exec_exos.plan_prechecks(device, target, plan, text)
    assert caught.value.reason_codes == ["port_management_vlan"]
    target = SimpleNamespace(firmware=FIRMWARE, audit_policy={"management_vlans": ["DATA"]})
    assert exec_exos.plan_prechecks(device, target, plan, text) == []


def test_prediction_places_the_lines_where_the_switch_prints_them():
    from netops_admin import prediction

    device = FakeExos()
    text = device.snapshot()
    plan = engine.build_plan("exos", text.encode(), port_request(), firmware=FIRMWARE, ports=INVENTORY)
    after = prediction.snapshot_after(text, plan)
    assert exos.Snapshot(after, FIRMWARE).entries("ports")["10"].attributes["admin-state"] == "disabled"
    cycle = engine.build_plan("exos", text.encode(), cycle_request(), firmware=FIRMWARE, ports=INVENTORY)
    after = prediction.snapshot_after(text, cycle)
    poe = exos.Snapshot(after, FIRMWARE)
    assert poe.entries("inline-power")["10"].attributes == {"admin-state": "disabled"}
    assert [command.module for command in poe.commands if command.text.startswith("disable inline-power")] == ["poe"]


# ---- port admin state through apply -------------------------------------------------------------------


def test_preview_reads_the_port_and_changes_nothing(tmp_path):
    device = FakeExos()
    result = execute.preview(make_runtime(tmp_path, device), "sw", port_request())
    assert result["result"] == "ready", result
    assert result["predicted"] == {"before": {}, "after": {"admin-state": "disabled"}}
    assert result["commands"] == ["disable ports 10"]
    assert "port 10 now: port state enabled, link state ready" in result["prechecks"]
    assert "port 10 has no LLDP neighbor and no learned MAC address" in result["prechecks"]
    assert device.applied_blocks == [] and not device.ports_down


def test_disable_is_confirmed_saved_and_undone(tmp_path):
    device = FakeExos()
    runtime = make_runtime(tmp_path, device)
    record = approved_apply(runtime, "sw", port_request())
    assert record["result"] == "confirmed", record
    assert device.ports_disabled == {"10"} and device.ports_down == {"10"}
    assert clean(device) and device.saves == 1
    safeguard = device.applied_blocks[0]
    assert [step[1] for step in safeguard[1:4]] == ["configure cli mode persistent",
                                                     "configure cli mode scripting ignore-error", "enable ports 10"]
    assert "check_identity_passed" in steps(record)
    back = execute.undo(runtime, record["change_id"], "port is needed again")
    assert back["result"] == "confirmed", back
    assert not device.ports_disabled and not device.ports_down and device.saves == 2
    assert plain_blocks(device)[0] == ["disable ports 10"] and plain_blocks(device)[2] == ["enable ports 10"]
    assert back["plan"]["predicted"] == {"before": {"admin-state": "disabled"}, "after": {}}


def test_lost_readback_after_disable_is_reverted_by_the_safeguard(tmp_path):
    device = FakeExos()

    def lose_check_account(fake, steps):
        if steps == ["disable ports 10"]:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    record = approved_apply(make_runtime(tmp_path, device), "sw", port_request())
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", record
    assert not device.ports_disabled and not device.ports_down and clean(device)


def test_check_account_seeing_the_port_still_enabled_reverts(tmp_path):
    device = FakeExos()
    original = device._command

    def command(words, automatic):
        result = original(words, automatic)
        if words == ["disable", "ports", "10"] and not automatic:
            device.ports_down.discard("10")
        return result

    device._command = command
    record = approved_apply(make_runtime(tmp_path, device), "sw", port_request())
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch", record
    assert not device.ports_disabled and clean(device)


@pytest.mark.parametrize(("key", "code"), [("7", "port_lldp_neighbor"), ("1", "port_lldp_neighbor"),
                                           ("3", "port_learned_mac"), ("9", "port_learned_mac")])
def test_ports_in_use_are_refused_before_any_change(tmp_path, key, code):
    device = FakeExos()
    runtime = make_runtime(tmp_path, device)
    result = execute.preview(runtime, "sw", port_request(key=key))
    assert result["result"] == "rejected" and result["reason_codes"] == [code]
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, "sw", port_request(key=key, request_id="req-admin-0002"))
    assert caught.value.reason_codes == [code]
    assert device.applied_blocks == []


def test_unreadable_usage_refuses_the_disable(tmp_path):
    device = FakeExos()
    device.lldp_text = "%% Invalid input detected at '^' marker.\n"
    result = execute.preview(make_runtime(tmp_path, device), "sw", port_request())
    assert result["reason_codes"] == ["port_usage_unreadable"]


@pytest.mark.parametrize("cut", [
    lambda text: _cut_after(text, "Port "),
    lambda text: _cut_after(text, "1 "),
    lambda text: _cut_after(text, "7 "),
])
def test_cut_off_lldp_refuses_the_disable_of_a_port_with_a_neighbor_in_the_missing_part(tmp_path, cut):
    device = FakeExos()
    device.lldp_text = cut(fixture("x440__03-lldp.out"))
    runtime = make_runtime(tmp_path, device)
    for key in ("7", "10"):
        result = execute.preview(runtime, "sw", port_request(key=key))
        assert result["result"] == "rejected" and result["reason_codes"] == ["port_usage_unreadable"], result
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, "sw", port_request(key="7", request_id="req-admin-0003"))
    assert caught.value.reason_codes == ["port_usage_unreadable"]
    assert device.applied_blocks == [] and not device.ports_down


def test_cut_off_fdb_refuses_the_disable(tmp_path):
    device = FakeExos()
    device.fdb_text = _cut_after(fixture("x440__02-show-fdb.out"), "-----")
    result = execute.preview(make_runtime(tmp_path, device), "sw", port_request())
    assert result["result"] == "rejected" and result["reason_codes"] == ["port_usage_unreadable"]
    assert device.applied_blocks == []


def test_complete_empty_lldp_list_lets_the_disable_through(tmp_path):
    device = FakeExos()
    lines = fixture("x440__03-lldp.out").splitlines(keepends=True)
    opening, closing = [number for number, line in enumerate(lines) if line.startswith("=====")]
    device.lldp_text = "".join(lines[:opening + 1] + lines[closing:])
    result = execute.preview(make_runtime(tmp_path, device), "sw", port_request(key="10"))
    assert result["result"] == "ready", result
    assert "port 10 has no LLDP neighbor and no learned MAC address" in result["prechecks"]


def test_enabling_a_disabled_port_with_an_lldp_neighbor_is_refused(tmp_path):
    # verification: the admin state is checked in both directions; port 7 has an LLDP neighbor in the fixture
    device = FakeExos()
    device.ports_disabled.add("7")
    device.ports_down.add("7")
    with pytest.raises(Rejected) as caught:
        approved_apply(make_runtime(tmp_path, device), "sw", port_request(key="7", state="enabled"))
    assert caught.value.reason_codes == ["port_lldp_neighbor"]
    assert device.applied_blocks == [] and device.ports_disabled == {"7"}


def test_enabling_a_disabled_access_port_is_confirmed(tmp_path):
    device = FakeExos()
    device.ports_disabled.add("10")
    device.ports_down.add("10")
    record = approved_apply(make_runtime(tmp_path, device), "sw", port_request(key="10", state="enabled"))
    assert record["result"] == "confirmed" and not device.ports_disabled
    assert "port 10 has no LLDP neighbor and no learned MAC address" in record["plan"]["prechecks"]


@pytest.mark.parametrize(("line", "code"), [
    ("configure vlan DATA add ports 5 tagged", "port_uplink"),
    ("enable sharing 5 grouping 5-6 algorithm address-based L2", "port_lag_member"),
])
def test_enabling_a_disabled_uplink_or_aggregated_port_is_refused(line, code):
    device = FakeExos()
    device.ports_disabled.add("5")
    text = device.snapshot().replace("configure vlan DATA add ports 1-4 untagged",
                                     "configure vlan DATA add ports 1-4 untagged\n" + line)
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", text.encode(), port_request(key="5", state="enabled"), firmware=FIRMWARE,
                          ports=INVENTORY)
    assert caught.value.reason_codes == [code]


def test_protected_port_is_refused(tmp_path):
    device = FakeExos()
    runtime = poe_runtime(tmp_path, device, protected={"ports": ["10"]})
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, "sw", port_request())
    assert caught.value.reason_codes == ["port_protected"]
    with pytest.raises(Rejected) as caught:
        approved_cycle(exos_poe, runtime, "sw", cycle_request())
    assert caught.value.reason_codes == ["port_protected"]
    assert device.applied_blocks == []


# ---- PoE cycle ----------------------------------------------------------------------------------------


def test_poe_cycle_preview_reads_the_state_and_changes_nothing(tmp_path):
    device = FakeExos()
    result = exos_poe.preview(poe_runtime(tmp_path, device), "sw", cycle_request())
    assert result["result"] == "ready", result
    assert result["operation"] == "poe-cycle" and result["table"] == "inline-power"
    assert result["cycle_commands"] == ["disable inline-power ports 10", "enable inline-power ports 10"]
    assert any(text.startswith("port 10 inline power before the cycle: searching") for text in result["prechecks"])
    assert device.applied_blocks == []


def test_poe_cycle_is_confirmed_with_the_configuration_unchanged(tmp_path):
    device = FakeExos()
    before = device.snapshot()
    runtime = poe_runtime(tmp_path, device)
    record = approved_cycle(exos_poe, runtime, "sw", cycle_request())
    assert record["result"] == "confirmed" and record["reason"] is None, record
    assert record["kind"] == "poe-cycle"
    assert plain_blocks(device)[:2] == [["disable inline-power ports 10"], ["enable inline-power ports 10"]]
    assert device.applied_blocks[0][3] == ("raw", "enable inline-power ports 10")
    assert device.applied_blocks[0][1] == ("raw", "configure cli mode persistent")
    for name in ("poe_before", "postcheck_passed", "audit_passed", "poe_off_observed", "poe_enable_applied",
                 "poe_enable_verified", "poe_on_observed", "configuration_saved"):
        assert name in steps(record)
    assert record["poe"]["before"]["state"] == "searching"
    assert (record["poe"]["off"]["configured"], record["poe"]["off"]["state"]) == ("disabled", "disabled")
    assert (record["poe"]["after"]["configured"], record["poe"]["after"]["state"]) == ("enabled", "searching")
    assert device.snapshot() == before and clean(device) and device.saves == 1
    events = [json.loads(line) for line in (tmp_path / "audit" / "audit.jsonl").read_text().splitlines()]
    start = next(event for event in events if event["event"] == "start")
    assert (start["table"], start["key"], start["op"]) == ("inline-power", "10", "update")
    assert events[-1]["event"] == "result" and events[-1]["result"] == "confirmed"


def test_powered_device_is_waited_for(tmp_path):
    device = FakeExos()
    device.powered_devices.add("10")
    record = approved_cycle(exos_poe, poe_runtime(tmp_path, device), "sw", cycle_request())
    assert record["result"] == "confirmed" and record["reason"] is None
    assert record["poe"]["before"]["state"] == "delivering" and record["poe"]["after"]["state"] == "delivering"


def test_powered_device_that_does_not_return_is_reported(tmp_path):
    device = FakeExos()
    device.powered_devices.add("10")

    def unplug(fake, steps):
        if steps == ["disable inline-power ports 10"]:
            fake.pd_seconds = None

    device.on_apply = unplug
    record = approved_cycle(exos_poe, poe_runtime(tmp_path, device), "sw", cycle_request())
    assert record["result"] == "confirmed" and record["reason"] == exos_poe.PD_NOT_BACK
    assert record["poe"]["after"]["state"] == "searching"
    assert not device.poe_disabled and clean(device)


def test_power_that_stays_off_is_settled_by_the_safeguard(tmp_path):
    device = FakeExos()

    def stick(fake, steps):
        if steps == ["enable inline-power ports 10"]:
            fake.poe_stuck_off = True

    device.on_apply = stick
    record = approved_cycle(exos_poe, poe_runtime(tmp_path, device), "sw", cycle_request())
    assert record["result"] == "reverted" and record["reason"] == "check identity mismatch", record
    assert not device.poe_disabled and clean(device)


def test_lost_readback_during_the_cycle_is_reverted_by_the_safeguard(tmp_path):
    device = FakeExos()

    def lose_check_account(fake, steps):
        if steps == ["disable inline-power ports 10"]:
            fake.check_unreadable = True

    device.on_apply = lose_check_account
    record = approved_cycle(exos_poe, poe_runtime(tmp_path, device), "sw", cycle_request())
    assert record["result"] == "reverted" and record["reason"] == "check identity unavailable", record
    assert not device.poe_disabled and not device.poe_off and clean(device)
    assert ["enable inline-power ports 10"] not in plain_blocks(device)


def test_failed_enable_is_left_to_the_safeguard(tmp_path):
    device = FakeExos()
    device.on_apply = lambda fake, steps: setattr(fake, "fail_at_line",
                                                  1 if steps == ["enable inline-power ports 10"] else None)
    record = approved_cycle(exos_poe, poe_runtime(tmp_path, device), "sw", cycle_request())
    assert record["result"] == "reverted" and record["reason"] == "change failed", record
    assert "poe_enable_failed" in steps(record)
    assert not device.poe_disabled and not device.poe_off and clean(device)


def test_poe_cycle_on_a_port_without_poe_is_refused(tmp_path):
    device = FakeExos()
    runtime = poe_runtime(tmp_path, device)
    result = exos_poe.preview(runtime, "sw", cycle_request(port="13"))
    assert result["result"] == "rejected" and result["reason_codes"] == ["poe_not_capable"]
    with pytest.raises(Rejected) as caught:
        approved_cycle(exos_poe, runtime, "sw", cycle_request(port="13", request_id="req-poe-0002"))
    assert caught.value.reason_codes == ["poe_not_capable"]
    assert device.applied_blocks == []


def test_port_without_poe_gives_its_code_with_the_measured_exit_status(tmp_path):
    device = FakeExos()
    for name, port in (("x435__27-ip-nopoe.out", "9"), ("x440__27-ip-nopoe.out", "13")):
        measured = fixture(name)
        assert exos.poe_not_capable_answer(250, measured, port)
        assert not exos.poe_not_capable_answer(0, measured, port)
        assert not exos.poe_not_capable_answer(254, measured, port)
        assert not exos.poe_not_capable_answer(250, measured, "1")
        assert not exos.poe_not_capable_answer(250, measured + "%% something else\n", port)
    assert device.query_status("show inline-power info ports 13")[0] == 250
    with pytest.raises(Exception) as caught:
        device.query("show inline-power info ports 13")
    assert "exit status 250" in str(caught.value)
    plan = {"key": "13", "prechecks": []}
    with pytest.raises(exos.NotInlinePower) as refused:
        exec_exos._poe_prechecks(device, None, plan, "")
    assert refused.value.reason_codes == ["poe_not_capable"]


@pytest.mark.parametrize(("rc", "text"), [
    (250, "Port 13 is not inline-power capable\nPort 14 is not inline-power capable\n"),
    (250, "%% Invalid input detected at '^' marker.\n"),
    (254, "Port 13 is not inline-power capable\n"),
    (1, ""),
])
def test_other_failed_inline_power_queries_stay_refused_without_the_poe_code(tmp_path, rc, text):
    device = FakeExos()
    device.query_status = lambda command: (rc, text)
    result = exos_poe.preview(poe_runtime(tmp_path, device), "sw", cycle_request(port="13"))
    assert result["result"] == "rejected" and result.get("reason_codes") != ["poe_not_capable"], result
    assert device.applied_blocks == []


def test_poe_cycle_on_a_switch_without_poe_is_refused(tmp_path):
    device = FakeExos()
    device.poe_ports = set()
    original = device.query_status
    device.query_status = lambda command: ((0, fixture("x435__11-ip-info-all.out"))
                                           if command.startswith("show inline-power info ports") else original(command))
    result = exos_poe.preview(poe_runtime(tmp_path, device), "sw", cycle_request())
    assert result["reason_codes"] == ["poe_unsupported"]


def test_poe_cycle_on_disabled_inline_power_is_refused(tmp_path):
    device = FakeExos()
    device.poe_disabled.add("10")
    device.poe_off.add("10")
    with pytest.raises(Rejected) as caught:
        approved_cycle(exos_poe, poe_runtime(tmp_path, device), "sw", cycle_request())
    assert caught.value.reason_codes == ["poe_disabled"]
    device = FakeExos()
    device.poe_off.add("10")
    result = exos_poe.preview(poe_runtime(tmp_path / "second", device), "sw", cycle_request())
    assert result["reason_codes"] == ["poe_disabled"]


def test_poe_cycle_has_no_undo(tmp_path):
    device = FakeExos()
    runtime = poe_runtime(tmp_path, device)
    record = approved_cycle(exos_poe, runtime, "sw", cycle_request())
    for call in (execute.undo, execute.preview_undo):
        with pytest.raises(Rejected) as caught:
            call(runtime, record["change_id"], "investigated")
        assert caught.value.reason_codes == ["undo_not_applicable"]
    assert len(plain_blocks(device)) == 3


def test_poe_cycle_counts_against_the_change_budget(tmp_path):
    device = FakeExos()
    runtime = poe_runtime(tmp_path, device, limits=dict(DEFAULT_LIMITS, changes_per_device_per_hour=1))
    assert approved_cycle(exos_poe, runtime, "sw", cycle_request())["result"] == "confirmed"
    with pytest.raises(BudgetExhausted) as caught:
        approved_cycle(exos_poe, runtime, "sw", cycle_request(request_id="req-poe-0003"))
    assert caught.value.reason_codes == ["budget_exhausted"]


def test_poe_cycle_needs_enrollment(tmp_path):
    device = FakeExos()
    runtime = poe_runtime(tmp_path, device)
    runtime.store.clear_enrollment("sw")
    with pytest.raises(Rejected) as caught:
        approved_cycle(exos_poe, runtime, "sw", cycle_request())
    assert caught.value.reason_codes == ["enrollment_required"]
    assert device.applied_blocks == []


def test_repeated_request_id_returns_the_cycle_without_running_it_again(tmp_path):
    device = FakeExos()
    runtime = poe_runtime(tmp_path, device)
    first = approved_cycle(exos_poe, runtime, "sw", cycle_request())
    again = approved_cycle(exos_poe, runtime, "sw", cycle_request())
    assert again["change_id"] == first["change_id"] and len(plain_blocks(device)) == 3


def test_interrupted_cycle_is_settled_by_recover(tmp_path):
    device = FakeExos()

    class Interrupted(BaseException):
        pass

    def interrupt(fake, steps):
        if steps == ["disable inline-power ports 10"]:
            fake.on_apply = None
            raise Interrupted()

    device.on_apply = interrupt
    runtime = poe_runtime(tmp_path, device)
    with pytest.raises(Interrupted):
        approved_cycle(exos_poe, runtime, "sw", cycle_request())
    settled = execute.recover(runtime, "sw")
    assert [(record["result"], record["reason"]) for record in settled] == [("reverted", "interrupted")]
    assert "cycle_proven" not in steps(settled[0]) and "cycle_unproven" not in steps(settled[0])
    assert not device.poe_disabled and not device.poe_off and clean(device)


# ---- 1.0.10 B2: safeguard margin of the cycle ----------------------------------------------------------


def test_cycle_budget_is_the_measured_reads_on_top_of_the_waits():
    # verification ops.log: show commands at most 2 s, show configuration at most 4 s (1 s resolution)
    assert (exos_poe.READ_SECONDS, exos_poe.SNAPSHOT_SECONDS, exos_poe.WRITE_SECONDS) == (2, 4, 4)
    assert exos_poe._wait_reads(exos_poe.OFF_WAIT_SECONDS) == 9 and exos_poe._wait_reads(exos_poe.ON_WAIT_SECONDS) == 31
    assert exos_poe.CYCLE_SECONDS == 3 * 4 + 2 * 4 + (15 + 9 * 2) + (60 + 31 * 2) == 175


@pytest.mark.parametrize(("safeguard", "margin", "admitted"), [
    (180, 45, False), (220, 45, False), (221, 45, True), (190, 15, False), (191, 15, True),
])
def test_cycle_without_margin_is_refused_before_any_read_or_write(tmp_path, safeguard, margin, admitted):
    device = FakeExos()
    runtime = make_runtime(tmp_path, device, safeguard_seconds=safeguard, confirm_margin_seconds=margin)
    if admitted:
        assert exos_poe.preview(runtime, "sw", cycle_request())["result"] == "ready"
        record = approved_cycle(exos_poe, runtime, "sw", cycle_request())
        assert record["result"] == "confirmed" and "margin_checked" in steps(record), record
        return
    for call in (exos_poe.preview, exos_poe.apply):
        with pytest.raises(Rejected) as caught:
            call(runtime, "sw", cycle_request())
        assert caught.value.reason_codes == ["safeguard_margin_insufficient"]
        assert "set safeguard_seconds of device sw to at least %d" % (176 + margin) in caught.value.reasons[0]
        assert caught.value.reason_details[0]["required_safeguard_seconds"] == 176 + margin
    assert device.applied_blocks == [] and runtime.store.records() == []
    assert runtime.store.rejections_since(float("-inf")) == 2


def _slow_install(monkeypatch, device, seconds):
    """The safeguard installation takes the given time on the switch (fake clock), as a slow session would."""
    original = exec_exos.install_safeguard

    def install(access, record, plan, target, spec):
        problems = original(access, record, plan, target, spec)
        device.advance(seconds)
        return problems

    monkeypatch.setattr(exec_exos, "install_safeguard", install)


def test_cycle_is_refused_on_the_switch_clock_before_power_is_touched(tmp_path, monkeypatch):
    device = FakeExos()
    before = device.snapshot()
    _slow_install(monkeypatch, device, 30)
    runtime = poe_runtime(tmp_path, device)
    record = approved_cycle(exos_poe, runtime, "sw", cycle_request())
    assert (record["result"], record["reason"]) == ("rejected", exos_poe.MARGIN_REASON), record
    assert record["reason_codes"] == ["safeguard_margin_insufficient"]
    names = steps(record)
    assert names[names.index("poe_before"):] == ["poe_before", "cycle_refused", "safeguard_removed",
                                                 "configuration_saved"]
    assert record["steps"][names.index("cycle_refused")]["detail"] == "210 s left, 175 s cycle, 45 s margin"
    assert not any(block[0].startswith(("disable inline-power", "enable inline-power"))
                   for block in plain_blocks(device))
    assert not device.poe_off and not device.history and clean(device) and device.snapshot() == before
    assert runtime.store.blocked("sw") is None


def test_enough_time_left_on_the_switch_clock_runs_the_cycle(tmp_path, monkeypatch):
    device = FakeExos()
    _slow_install(monkeypatch, device, 15)
    record = approved_cycle(exos_poe, poe_runtime(tmp_path, device), "sw", cycle_request())
    assert record["result"] == "confirmed" and record["reason"] is None, record
    detail = record["steps"][steps(record).index("margin_checked")]["detail"]
    assert detail == "225 s left, 175 s cycle, 45 s margin"
    assert not device.history


def test_unreadable_clock_refuses_the_cycle_and_removes_the_safeguard(tmp_path, monkeypatch):
    device = FakeExos()
    original = exec_exos.clock
    calls = []

    def clock(access):
        calls.append(True)
        if len(calls) > 1:
            raise RuntimeError("show switch unavailable")
        return original(access)

    monkeypatch.setattr(exec_exos, "clock", clock)
    record = approved_cycle(exos_poe, poe_runtime(tmp_path, device), "sw", cycle_request())
    assert (record["result"], record["reason"], record["reason_codes"]) == (
        "rejected", "device clock", ["device_clock_unreadable"])
    assert "change_start" not in steps(record) and not device.poe_off and clean(device)


# ---- 1.0.10 B2: recover of a cycle interrupted after confirm_start -------------------------------------


class Interrupted(BaseException):
    pass


def _interrupted_after_confirm_start(tmp_path, port="8"):
    """Run a cycle and stop the process inside the safeguard removal: confirm_start is journaled, the
    safeguard is still installed."""
    device = FakeExos()

    def interrupt(fake, block):
        if block and isinstance(block[0], str) and block[0].startswith("delete upm timer"):
            fake.on_apply = None
            raise Interrupted()

    device.on_apply = interrupt
    runtime = poe_runtime(tmp_path, device)
    with pytest.raises(Interrupted):
        approved_cycle(exos_poe, runtime, "sw", cycle_request(port=port))
    record = runtime.store.running("sw")[0]
    assert steps(record)[-1] == "confirm_start" and device.timers and device.profiles
    return device, runtime


def test_recover_confirms_a_proven_cycle_and_removes_the_safeguard(tmp_path):
    device, runtime = _interrupted_after_confirm_start(tmp_path)
    # measured on X435 port 8 after the cycle (verification, A6): Configured Admin State enabled, searching
    device.poe_detail_measured["8"] = fixture("x435__A6-ip-detail-post.out")
    settled = execute.recover(runtime, "sw")
    assert [(record["result"], record["reason"]) for record in settled] == [("confirmed", exos_poe.CYCLE_CONFIRMED)]
    names = steps(settled[0])
    assert names[names.index("recovery_start"):] == ["recovery_start", "cycle_proven", "safeguard_removed",
                                                     "configuration_saved"]
    recovered = settled[0]["poe"]["recovered"]
    assert (recovered["configured"], recovered["state"]) == ("enabled", "searching")
    assert not device.history, "the safeguard must not have fired"
    assert clean(device) and not device.poe_disabled and runtime.store.blocked("sw") is None
    assert [block for block in plain_blocks(device) if block[0].startswith("disable inline-power")] == [
        ["disable inline-power ports 8"]]


@pytest.mark.parametrize("measured", ["x435__57-ip-detail-en.out", "x435__52-ip-detail-dis.out"])
def test_recover_without_fresh_proof_lets_the_safeguard_restore_power(tmp_path, measured):
    device, runtime = _interrupted_after_confirm_start(tmp_path)
    # measured on X435 port 8: 57 right after the enable (enabled, power still disabled), 52 after the disable
    device.poe_detail_measured["8"] = fixture(measured)
    settled = execute.recover(runtime, "sw")
    assert [(record["result"], record["reason"]) for record in settled] == [("reverted", exos_poe.CYCLE_NOT_PROVEN)]
    names = steps(settled[0])
    assert "cycle_unproven" in names and "cycle_proven" not in names
    assert settled[0]["steps"][names.index("cycle_unproven")]["detail"].startswith("power not on: ")
    assert device.history, "power is restored by the safeguard"
    assert clean(device) and not device.poe_disabled and not device.poe_off


def test_recover_with_an_unreadable_check_account_does_not_claim_the_cycle(tmp_path):
    device, runtime = _interrupted_after_confirm_start(tmp_path)
    device.check_unreadable = True
    settled = execute.recover(runtime, "sw")
    assert [(record["result"], record["reason"]) for record in settled] == [("reverted", exos_poe.CYCLE_NOT_PROVEN)]
    detail = settled[0]["steps"][steps(settled[0]).index("cycle_unproven")]["detail"]
    assert detail == "fresh read failed: RuntimeError"
    assert device.history and clean(device)


def test_recover_without_the_journaled_off_and_on_does_not_claim_the_cycle(tmp_path):
    device, runtime = _interrupted_after_confirm_start(tmp_path)
    record = runtime.store.running("sw")[0]
    record["steps"] = [step for step in record["steps"] if step["step"] != "poe_off_observed"]
    runtime.store.save(record)
    settled = execute.recover(runtime, "sw")
    assert [(record["result"], record["reason"]) for record in settled] == [("reverted", exos_poe.CYCLE_NOT_PROVEN)]
    assert settled[0]["steps"][steps(settled[0]).index("cycle_unproven")]["detail"] == \
        "the journal does not show power off and on again"
    assert device.history and clean(device)


def test_recover_of_a_cycle_whose_safeguard_is_absent_is_unchanged(tmp_path):
    device = FakeExos()

    def interrupt(fake, block):
        if block and block[0] == ("ask", "save configuration", b"(y/N)"):
            fake.on_apply = None
            raise Interrupted()

    device.on_apply = interrupt
    runtime = poe_runtime(tmp_path, device)
    with pytest.raises(Interrupted):
        approved_cycle(exos_poe, runtime, "sw", cycle_request())
    assert clean(device)
    settled = execute.recover(runtime, "sw")
    assert [(record["result"], record["reason"]) for record in settled] == [
        ("confirmed", "confirmed before the interruption")]
    names = steps(settled[0])
    assert names[names.index("recovery_start"):] == ["recovery_start", "configuration_saved"]
    assert not device.history


# ---- profile and doctor -------------------------------------------------------------------------------


def test_inline_power_profile_updates_admin_state():
    loaded = profiles.load_profiles()[("exos", "inline-power")]
    assert loaded.action is None and loaded.exact_versions and loaded.versions == ("33.7.1.6",)
    assert loaded.measured and not loaded.provisional
    assert "delivering" in loaded.rollback_evidence and "reset inline-power" in loaded.rollback_evidence
    # An untested firmware version (assembled to avoid an IPv4-shaped literal) finds the profile and is reported
    untested = "33.7." + "1.7"
    assert profiles.find_profile("exos", "inline-power", untested).versions == loaded.versions
    assert profiles.firmware_support(loaded, untested)["status"] == "untested"
    data = json.loads((Path(profiles.__file__).parent / "profiles" / "exos-inline-power.json").read_text())
    with pytest.raises(profiles.ProfileError):
        profiles.parse_profile(dict(data, platform="nxos", action="poe-cycle"))
    with pytest.raises(profiles.ProfileError):
        profiles.parse_profile(dict(data, action="reboot"))


def test_doctor_lists_the_cycle_as_its_own_operation():
    operations = readiness._operations("exos", FIRMWARE)
    assert operations["poe-cycle"] == "poe-cycle" and operations["inline-power"] == operations["ports"] == "update"
    assert readiness._operations("exos", "33.6.1.14")["poe-cycle"] == "poe-cycle (untested on 33.6.1.14)"
    assert readiness._operations("exos", "33.6.1.14")["ports"] == "update"
    assert readiness._firmware_support("exos", "33.6.1.14")["inline-power"]["status"] == "untested"


def test_cli_poe_cycle_preview_and_apply(monkeypatch, tmp_path, capsys):
    from netops_admin import cli, config

    device = FakeExos()
    runtime = poe_runtime(tmp_path, device)
    monkeypatch.setattr(config, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "build_runtime", lambda _config: runtime)
    base = ["poe-cycle", "--config", str(tmp_path / "admin.json"), "--device", "sw", "--port", "10",
            "--reason", "access point hangs", "--user-request", "restart PoE on port 10"]
    assert cli.main(base + ["--request-id", "req-cli-0001", "--preview"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["result"] == "ready" and device.applied_blocks == []
    assert cli.main(base + ["--request-id", "req-cli-0002"]) == cli.EXIT_REJECTED
    assert json.loads(capsys.readouterr().out)["reason_codes"] == ["plan_changed"] and device.applied_blocks == []
    assert cli.main(base + ["--request-id", "req-cli-0002", "--expect-plan-sha256", preview["plan_sha256"]]) == 0
    assert json.loads(capsys.readouterr().out)["result"] == "confirmed"
    # the port without PoE is refused by the plan itself, before any plan hash is compared
    assert cli.main(base[:6] + ["13"] + base[7:] + ["--request-id", "req-cli-0003",
                                                   "--expect-plan-sha256", "0" * 64]) == cli.EXIT_REJECTED
    assert json.loads(capsys.readouterr().out)["reason_codes"] == ["poe_not_capable"]
