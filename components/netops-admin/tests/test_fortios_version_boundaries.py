from dataclasses import replace

import pytest

from fake_020 import FortiOS800
from fake_fortios import FakeFortiOS
from netops_admin import execute, profiles
from netops_admin.errors import Rejected
from test_execute import make_runtime, request


GROUP_AND_DHCP = [
    ("firewall addrgrp", "update", "group-example", {"member": ["spare-host"]}),
    ("system dhcp server/reserved-address", "create", "1:2",
     {"ip": "192.0.2.102", "mac": "00:00:5e:00:53:02"}),
    ("system dhcp server/reserved-address", "update", "1:1", {"description": "changed"}),
    ("system dhcp server/reserved-address", "delete", "1:1", {}),
]


@pytest.mark.parametrize(("table", "op", "key", "changes"), GROUP_AND_DHCP)
def test_800_build0167_runs_the_measured_group_and_dhcp_operations(tmp_path, table, op, key, changes):
    device = FortiOS800()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request(table=table, op=op, key=key, changes=changes))
    assert record["result"] == "confirmed"
    assert record["plan"]["firmware"] == "8.0.0 build0167"
    assert not device.actions and not device.triggers and not device.stitches


@pytest.mark.parametrize(("release", "build"), [("8.0.0", "0168"), ("8.0.1", "0245"), ("8.0.2", "0251")])
@pytest.mark.parametrize(("table", "op", "key", "changes"), GROUP_AND_DHCP)
def test_other_800_builds_refuse_group_and_dhcp_before_any_device_write(tmp_path, release, build, table, op, key, changes):
    class OtherFirmware(FortiOS800):
        def snapshot(self):
            return super().snapshot().replace("8.0.0-FW-build0167", release + "-FW-build" + build)

    device = OtherFirmware()
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(table=table, op=op, key=key, changes=changes))
    assert any("not measured on firmware" in reason for reason in caught.value.reasons)
    assert not device.applied_blocks
    assert not device.actions and not device.triggers and not device.stitches


@pytest.mark.parametrize("configured", ["7.6.7 build3704", "8.0.0 build0168", "8.0.1 build0245", "8.0.2 build0251"])
def test_live_snapshot_version_cannot_be_overridden_by_configuration(tmp_path, configured):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    runtime.config.devices["lab"] = replace(runtime.config.devices["lab"], firmware=configured)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert any("differs from the expected" in reason for reason in caught.value.reasons)
    assert not device.applied_blocks


@pytest.mark.parametrize(("release", "build"), [("8.0.0", "0168"), ("8.0.1", "0245"), ("8.0.3", "0300"), ("8.1.0", "0001")])
def test_unmeasured_fortios_build_never_inherits_800_command_support(tmp_path, release, build):
    class OtherFirmware(FakeFortiOS):
        def snapshot(self):
            return super().snapshot().replace("8.0.0-FW-build0167", release + "-FW-build" + build)

    device = OtherFirmware()
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert any("not measured on firmware" in reason for reason in caught.value.reasons)
    assert not device.applied_blocks


FORTIOS_TABLES = ["firewall address", "firewall addrgrp", "system dhcp server/reserved-address", "firewall policy"]


WEBHOOK_LISTED = {("firewall address", "8.0.2 build0251"), ("firewall policy", "8.0.2 build0251")}
UNLISTED_800 = [(table, firmware) for firmware in ("8.0.0 build0168", "8.0.1 build0245", "8.0.2 build0251", "8.0.3 build0300")
                for table in FORTIOS_TABLES if (table, firmware) not in WEBHOOK_LISTED]


@pytest.mark.parametrize(("table", "firmware"), UNLISTED_800)
def test_every_unlisted_800_build_is_refused_with_the_fortios_80_auto_script_change(table, firmware):
    with pytest.raises(Rejected) as caught:
        profiles.find_profile("fortios", table, firmware)
    reason = " ".join(caught.value.reasons)
    assert "not measured on firmware" in reason
    assert "FortiOS 8.0" in reason and "auto-script" in reason and "Fortinet" in reason


def test_policy_refuses_800_build0167_with_the_same_reason():
    with pytest.raises(Rejected) as caught:
        profiles.find_profile("fortios", "firewall policy", "8.0.0 build0167")
    assert "auto-script" in " ".join(caught.value.reasons)


@pytest.mark.parametrize("firmware", ["8.1.0 build0001", "7.4.9 build2000"])
def test_the_auto_script_reason_is_only_given_for_800(firmware):
    with pytest.raises(Rejected) as caught:
        profiles.find_profile("fortios", "firewall address", firmware)
    assert "auto-script" not in " ".join(caught.value.reasons)


def test_76_family_stays_accepted():
    assert profiles.find_profile("fortios", "firewall address", "7.6.9 build4000").table == "firewall address"


@pytest.mark.parametrize("firmware", ["8.0.1 build0245", "8.0.2 build0300"])
def test_the_800_refusal_names_the_webhook_safeguard_not_a_missing_one(firmware):
    with pytest.raises(Rejected) as caught:
        profiles.find_profile("fortios", "firewall addrgrp", firmware)
    reason = " ".join(caught.value.reasons)
    assert "webhook safeguard" in reason
    assert "cannot revert" not in reason
