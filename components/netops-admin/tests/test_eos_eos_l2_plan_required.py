"""EOS L2 tables (eos_l2.TABLES) are applied only with the approved preview's plan_sha256."""

import re

import pytest

from test_eos_eos_mlag_admin import CHANNEL, PORT, LabEOS, change
from test_eos import make_runtime
from netops_admin import execute
from netops_admin.errors import Rejected


def stp_vlan_case():
    device = LabEOS()
    device.lines[device.lines.index("spanning-tree mode mstp")] = "spanning-tree mode rapid-pvst"
    device._add_vlan("3910")
    device.saved = list(device.lines)
    return device, change("stp-vlan", "3910", {"priority": 20480}), True


def member_case():
    device = LabEOS()
    device._add_interface(CHANNEL)
    device._set(PORT, re.compile(r".*"), "shutdown")
    device.saved = list(device.lines)
    return device, change("port-channel-member", PORT, {"group": 900, "mode": "active"}), False


@pytest.mark.parametrize("case", [stp_vlan_case, member_case], ids=["stp-vlan", "port-channel-member"])
def test_l2_apply_without_plan_hash_is_refused_and_writes_nothing(tmp_path, case):
    device, item, unmeasured = case()
    runtime = make_runtime(tmp_path, device, firmware=device.firmware, simulate_unmeasured_profiles=unmeasured)
    preview = execute.preview(runtime, "lab-ceos", item)
    assert preview["result"] == "ready", preview
    baseline = device.snapshot()

    with pytest.raises(Rejected) as denied:
        execute.apply(runtime, "lab-ceos", item)
    assert denied.value.reason_codes == ["plan_changed"]
    assert not device.applied_blocks
    assert device.snapshot() == baseline and device.lines == device.saved
    assert not device.sessions and device.timer is None

    record = execute.apply(runtime, "lab-ceos", item, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record["steps"])
    assert device.applied_blocks and device.snapshot() != baseline
