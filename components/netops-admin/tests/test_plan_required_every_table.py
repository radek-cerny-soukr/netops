"""Every profile apply needs the approved preview's plan_sha256, on every platform and for every table.

The tables below used to be applied without the hash (only some tables of a platform required it). Each case goes
through the real path execute.preview -> execute.apply with the platform's fake transport and measured fixtures:
without the hash the apply is refused with plan_changed before it opens a device session or records an operation;
with the plan_sha256 of the preview the same request is confirmed on the device.
"""
from __future__ import annotations

import pytest

from fake_eos import FakeEos
from fake_exos import FakeExos
from fake_fortiadc_admin import FakeADC
from fake_fortios import FakeFortiOS
from fake_ios import FakeIos
from fake_junos import FakeJunos
from fake_nxos import FakeNxos

import test_eos
import test_eos_eos_static_routing as eos_l3
import test_execute
import test_execute_exos
import test_fortiadc_admin_runtime as adc
import test_ios
import test_junos
import test_nxos
from netops_admin import exec_nxos, execute
from netops_admin.errors import Rejected


def eos_interface(tmp_path, _monkeypatch):
    device = FakeEos()
    return device, test_eos.make_runtime(tmp_path, device), "lab-ceos", test_eos.request()


def eos_static_route(tmp_path, _monkeypatch):
    device = eos_l3.FakeL3Eos()
    item = eos_l3.change("static-route", "vrf:%s:198.51.100.0/24" % eos_l3.VRF, {"next-hop": "192.0.2.1"}, "create")
    return device, test_eos.make_runtime(tmp_path, device), "lab-ceos", item


def ios_node(node):
    def case(tmp_path, _monkeypatch):
        device = FakeIos(node)
        return device, test_ios.make_runtime(tmp_path, device), "lab-ios", test_ios.request(device)
    return case


def nxos_interface(tmp_path, monkeypatch):
    device = FakeNxos()
    monkeypatch.setattr(exec_nxos, "PAUSE", device.advance)
    return device, test_nxos.make_runtime(tmp_path, device), "lab-nxos", test_nxos.request()


def exos_vlan(tmp_path, _monkeypatch):
    device = FakeExos()
    return device, test_execute_exos.make_runtime(tmp_path, device), "sw", test_execute_exos.request()


def junos_interface(tmp_path, _monkeypatch):
    device = FakeJunos()
    return device, test_junos.make_runtime(tmp_path, device), test_junos.NAME, test_junos.request()


def fortios_address(tmp_path, _monkeypatch):
    device = FakeFortiOS()
    return device, test_execute.make_runtime(tmp_path, device), "lab", test_execute.request()


def fortiadc_pool_member(tmp_path, _monkeypatch):
    device = FakeADC()
    return device, adc.make_runtime(tmp_path, device), "adc", adc.request()


CASES = {
    "eos-interface": eos_interface,
    "eos-static-route": eos_static_route,
    "ios-interface": ios_node("iosvl2"),
    "iosxe-interface": ios_node("iolxe-l2"),
    "nxos-interface": nxos_interface,
    "exos-vlan": exos_vlan,
    "junos-interface": junos_interface,
    "fortios-firewall-address": fortios_address,
    "fortiadc-pool-member": fortiadc_pool_member,
}


@pytest.mark.parametrize("case", list(CASES.values()), ids=list(CASES))
def test_apply_without_the_preview_hash_is_refused_before_the_device_and_with_it_confirmed(tmp_path, monkeypatch, case):
    device, runtime, name, item = case(tmp_path, monkeypatch)
    platform = runtime.config.devices[name].platform
    preview = execute.preview(runtime, name, item)
    assert preview["result"] == "ready", preview
    assert preview["table"] == item.table and preview["platform"] == platform

    sessions = []
    factory = runtime.access_factory
    runtime.access_factory = lambda target: sessions.append(target.name) or factory(target)
    blocks = [list(block) for block in device.applied_blocks]
    records = len(runtime.store.records())

    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, name, item)
    assert refused.value.reason_codes == ["plan_changed"]
    assert "plan_sha256" in refused.value.reasons[0]
    assert sessions == []
    assert [list(block) for block in device.applied_blocks] == blocks
    assert runtime.store.request(item.request_id) is None and len(runtime.store.records()) == records

    record = execute.apply(runtime, name, item, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), [step["step"] for step in record["steps"]])
    assert sessions and len(device.applied_blocks) > len(blocks)
    assert runtime.store.request(item.request_id)["change_id"] == record["change_id"]
