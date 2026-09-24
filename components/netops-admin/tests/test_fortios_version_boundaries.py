from dataclasses import replace

import pytest

from fake_fortios import FakeFortiOS
from netops_admin import execute
from netops_admin.errors import Rejected
from test_execute import make_runtime, request


@pytest.mark.parametrize(("table", "op", "key", "changes"), [
    ("firewall addrgrp", "update", "group-example", {"member": ["spare-host"]}),
    ("system dhcp server/reserved-address", "create", "1:2",
     {"ip": "192.0.2.102", "mac": "00:00:5e:00:53:02"}),
    ("system dhcp server/reserved-address", "update", "1:1", {"description": "changed"}),
    ("system dhcp server/reserved-address", "delete", "1:1", {}),
])
def test_800_refuses_76_only_operations_before_any_device_write(tmp_path, table, op, key, changes):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request(table=table, op=op, key=key, changes=changes))
    assert any("not measured on firmware" in reason for reason in caught.value.reasons)
    assert not device.applied_blocks
    assert not device.actions and not device.triggers and not device.stitches


@pytest.mark.parametrize("configured", ["7.6.7 build3704", "8.0.0 build0168", "8.0.1 build0245"])
def test_live_snapshot_version_cannot_be_overridden_by_configuration(tmp_path, configured):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    runtime.config.devices["lab"] = replace(runtime.config.devices["lab"], firmware=configured)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert any("differs from the expected" in reason for reason in caught.value.reasons)
    assert not device.applied_blocks


@pytest.mark.parametrize(("release", "build"), [("8.0.0", "0168"), ("8.0.1", "0245"), ("8.1.0", "0001")])
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
