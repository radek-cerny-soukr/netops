from dataclasses import replace

import pytest

from fake_020 import FortiOS767, FortiOS800, table
from fake_fortios import FakeFortiOS
from fake_webhook import FakeFortiOSWebhook
from netops_admin import execute, fortios, mcp_server, profiles
from netops_admin.errors import Rejected
from test_execute import audit_lines, make_runtime, request


GROUP_AND_DHCP = [
    ("firewall addrgrp", "update", "group-example", {"member": ["spare-host"]}),
    ("system dhcp server/reserved-address", "create", "1:2",
     {"ip": "192.0.2.102", "mac": "00:00:5e:00:53:02"}),
    ("system dhcp server/reserved-address", "update", "1:1", {"description": "changed"}),
    ("system dhcp server/reserved-address", "delete", "1:1", {}),
]
DHCP = [case for case in GROUP_AND_DHCP if case[0].startswith("system dhcp")]


def req(table, op, key, changes):
    # 1.0.12 G20: a DHCP reservation change names its impact and is applied from an approved preview
    extra = {"endpoint_impact": key} if table.startswith("system dhcp") else {}
    return request(table=table, op=op, key=key, changes=changes, **extra)


def approved(runtime, request_):
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "ready", preview
    return execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])


def firmware_class(base, release, build):
    return type("Firmware%s" % build, (base,), {"firmware": (release, build)})


class WebhookWithDhcp(FakeFortiOSWebhook):
    """The webhook fake (FortiOS 8.0.x from 8.0.1) whose snapshot also holds a group and a DHCP server."""

    def __init__(self):
        super().__init__()
        self.groups = {"group-example": {"member": "srv-web spare-host", "comment": "example"}}
        self.reservations = {"1": {"ip": "192.0.2.101", "mac": "00:00:5e:00:53:01", "description": "first"}}

    def snapshot(self):
        return super().snapshot() + table("firewall addrgrp", self.groups) + FortiOS767.dhcp(self)

    def check_query(self, command):
        if command == "show system dhcp server 1":
            return FortiOS767.dhcp(self)
        return super().check_query(command)


@pytest.mark.parametrize(("table", "op", "key", "changes"), GROUP_AND_DHCP)
def test_800_build0167_runs_the_measured_group_and_dhcp_operations(tmp_path, table, op, key, changes):
    device = FortiOS800()
    runtime = make_runtime(tmp_path, device)
    record = approved(runtime, req(table, op, key, changes))
    assert record["result"] == "confirmed"
    assert record["plan"]["firmware"] == "8.0.0 build0167"
    assert record["plan"]["firmware_support"]["status"] == "tested"
    assert not device.actions and not device.triggers and not device.stitches


@pytest.mark.parametrize(("table", "op", "key", "changes"), GROUP_AND_DHCP)
def test_untested_800_build_runs_group_and_dhcp_with_a_warning(tmp_path, table, op, key, changes):
    # G00-1: until 1.0.11 an unlisted build was refused before any write; it now runs with the cli-script
    # safeguard of 8.0.0 and the warning in the plan, the result, the audit and the notification
    device = firmware_class(FortiOS800, "8.0.0", "0168")()
    runtime = make_runtime(tmp_path, device)
    request_ = req(table, op, key, changes)
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "ready", preview
    support = preview["firmware_support"]
    assert support["status"] == "untested" and support["device_version"] == "8.0.0 build0168"
    assert "8.0.0 build0167" in support["tested_versions"]
    assert any(check.startswith("firmware 8.0.0 build0168 is not among the tested versions")
               for check in preview["prechecks"])
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert record["plan"]["firmware_support"] == support
    assert mcp_server.summary(record)["firmware_support"] == support
    start = next(event for event in audit_lines(tmp_path) if event["event"] == "start")
    assert start["firmware_tested"] is False
    assert not device.actions and not device.triggers and not device.stitches


@pytest.mark.parametrize(("release", "build"), [("8.0.1", "0245"), ("8.0.2", "0251"), ("8.0.3", "0300")])
@pytest.mark.parametrize(("table", "op", "key", "changes"), DHCP)
def test_dhcp_on_webhook_builds_is_planned_with_a_rest_inverse(tmp_path, release, build, table, op, key, changes):
    # 1.0.12 G20 (FP-24): from 8.0.1 the webhook safeguard returns a DHCP reservation through the REST API
    # system.dhcp/server/<id>/reserved-address/<id> (until 1.0.11 these builds refused it, safeguard_no_rest_inverse)
    device = firmware_class(WebhookWithDhcp, release, build)()
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab", req(table, op, key, changes))
    assert preview["result"] == "ready", preview
    assert preview["firmware_support"]["status"] == "untested"
    assert not device.applied_blocks and not device.actions and not device.triggers and not device.stitches
    assert runtime.store.records() == []


@pytest.mark.parametrize("configured", ["7.6.7 build3704", "8.0.0 build0168", "8.0.1 build0245", "8.0.2 build0251"])
def test_live_snapshot_version_cannot_be_overridden_by_configuration(tmp_path, configured):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    runtime.config.devices["lab"] = replace(runtime.config.devices["lab"], firmware=configured)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request())
    assert any("differs from the expected" in reason for reason in caught.value.reasons)
    assert not device.applied_blocks


@pytest.mark.parametrize(("base", "release", "build"), [
    (FakeFortiOS, "7.4.9", "2000"), (FakeFortiOS, "7.6.9", "4000"), (FakeFortiOS, "8.0.0", "0168"),
    (FakeFortiOSWebhook, "8.0.1", "0245"), (FakeFortiOSWebhook, "8.0.3", "0300"),
    (FakeFortiOSWebhook, "8.1.0", "0001"),
])
def test_untested_fortios_build_runs_the_address_with_its_safeguard_and_a_warning(tmp_path, base, release, build):
    device = firmware_class(base, release, build)()
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "confirmed", record
    assert record["plan"]["firmware_support"]["status"] == "untested"
    sent = [line for block in device.applied_blocks for line in block]
    webhook = fortios.webhook_firmware("%s build%s" % (release, build))
    assert ("set action-type webhook" in sent) is webhook
    assert ("set action-type cli-script" in sent) is not webhook


FORTIOS_TABLES = ["firewall address", "firewall addrgrp", "system dhcp server/reserved-address", "firewall policy"]
WEBHOOK_LISTED = {("firewall address", "8.0.2 build0251"), ("firewall policy", "8.0.2 build0251")}
UNLISTED_800 = [(table, firmware) for firmware in ("8.0.0 build0168", "8.0.1 build0245", "8.0.2 build0251", "8.0.3 build0300")
                for table in FORTIOS_TABLES if (table, firmware) not in WEBHOOK_LISTED]


@pytest.mark.parametrize(("table", "firmware"), UNLISTED_800)
def test_every_unlisted_800_build_is_untested_and_explains_the_80_safeguard(table, firmware):
    profile = profiles.find_profile("fortios", table, firmware)
    support = profiles.firmware_support(profile, firmware)
    assert support["status"] == "untested"
    assert "may or may not work as designed and tested" in support["message"]
    assert "FortiOS 8.0" in support["message"] and "auto-script" in support["message"]
    assert "webhook safeguard" in support["message"]


@pytest.mark.parametrize("firmware", ["7.4.9 build2000", "7.6.9 build4000"])
def test_the_auto_script_note_is_only_given_for_8x(firmware):
    support = profiles.firmware_support(profiles.find_profile("fortios", "firewall address", firmware), firmware)
    assert support["status"] == "untested" and "auto-script" not in support["message"]


def test_76_family_is_untested_not_inherited():
    # one rule for all versions (G00 §2.1): only listed builds are tested, there is no family inheritance
    profile = profiles.find_profile("fortios", "firewall address", "7.6.9 build4000")
    assert profile.table == "firewall address"
    assert profiles.firmware_support(profile, "7.6.9 build4000")["status"] == "untested"
    assert profiles.firmware_support(profile, "7.6.7 build3704")["status"] == "tested"
