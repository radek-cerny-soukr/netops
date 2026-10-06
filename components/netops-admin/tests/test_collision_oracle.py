from __future__ import annotations

import pytest
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request
from test_execute_exos import make_runtime as make_exos_runtime
from test_execute_exos import request as exos_request
from test_exos import plan as exos_plan
from test_exos import rejected as exos_rejected
from test_fortios import plan, rejected, replace

from netops_admin import execute
from netops_admin.config import DEFAULT_LIMITS
from netops_admin.errors import Rejected

FORTIOS_SECRETS = {
    "snmp community": 'config system snmp community\n    edit 1\n        set name "%s"\n    next\nend\n',
    "radius secret": 'config user radius\n    edit "lab-radius"\n        set server "192.0.2.50"\n'
                     '        set secret "%s"\n    next\nend\n',
    "radius secret ciphertext": 'config user radius\n    edit "lab-radius"\n        set server "192.0.2.50"\n'
                                '        set secret ENC %s\n    next\nend\n',
    "ipsec psk": 'config vpn ipsec phase1-interface\n    edit "lab-tunnel"\n        set psksecret "%s"\n    next\nend\n',
    "snmpv3 password": 'config system snmp user\n    edit "lab-v3"\n        set auth-pwd "%s"\n    next\nend\n',
    "route comment": 'config router static\n    edit 1\n        set comment "%s"\n    next\nend\n',
    "interface description": 'config system interface\n    edit "port9"\n        set description "%s"\n    next\nend\n',
}
EXOS_SECRETS = {
    "snmp community": "configure snmpv3 add community %s name %s user v1v2c_ro\n",
    "radius secret": 'configure radius mgmt-access primary server 192.0.2.50 1812 client-ip 192.0.2.2 vr VR-Mgmt'
                     ' shared-secret encrypted "%s"\n',
    "port description": 'configure ports 9 description-string "%s"\n',
    "location": 'configure snmp sysLocation "%s"\n',
    "tacacs secret": "configure tacacs primary server 192.0.2.51 49 client-ip 192.0.2.2 vr VR-Mgmt shared-secret %s\n",
}


class HoldingFortiOS(FakeFortiOS):
    def __init__(self, section):
        super().__init__()
        self.section = section

    def snapshot(self):
        return super().snapshot().replace("config firewall policy\n", self.section + "config firewall policy\n", 1)


class HoldingExos(FakeExos):
    def __init__(self, line):
        super().__init__()
        self.line = line

    def snapshot(self):
        return super().snapshot().replace("#\n# Module vlan configuration.\n",
                                          self.line + "#\n# Module vlan configuration.\n", 1)


def filled(template, value):
    return template.replace("%s", value)


def without_audit_count(result):
    return {name: value for name, value in result.items() if name != "audit_findings_before"}


def fortios_preview(tmp_path, section, value, **fields):
    device = HoldingFortiOS(filled(section, value))
    return execute.preview(make_runtime(tmp_path / value, device), "lab", request(**fields))


def exos_preview(tmp_path, line, value, **fields):
    device = HoldingExos(filled(line, value))
    return execute.preview(make_exos_runtime(tmp_path / value, device), "sw", exos_request(**fields))


@pytest.mark.parametrize("section", sorted(FORTIOS_SECRETS))
def test_fortios_preview_create_does_not_confirm_a_guessed_value(tmp_path, section):
    right = fortios_preview(tmp_path, FORTIOS_SECRETS[section], "guessed-value", key="guessed-value")
    wrong = fortios_preview(tmp_path, FORTIOS_SECRETS[section], "other-value", key="guessed-value")
    assert right == wrong
    assert right["result"] == "ready", right["reasons"]


@pytest.mark.parametrize("section", sorted(FORTIOS_SECRETS))
def test_fortios_preview_delete_does_not_confirm_a_guessed_value(tmp_path, section):
    fields = {"op": "delete", "key": "spare-host", "changes": {}}
    right = fortios_preview(tmp_path, FORTIOS_SECRETS[section], "spare-host", **fields)
    wrong = fortios_preview(tmp_path, FORTIOS_SECRETS[section], "other-value", **fields)
    assert without_audit_count(right) == without_audit_count(wrong)
    assert right["result"] == "ready", right["reasons"]


@pytest.mark.parametrize("line", sorted(EXOS_SECRETS))
def test_exos_preview_create_does_not_confirm_a_guessed_value(tmp_path, line):
    right = exos_preview(tmp_path, EXOS_SECRETS[line], "guessed", key="guessed")
    wrong = exos_preview(tmp_path, EXOS_SECRETS[line], "other", key="guessed")
    assert right == wrong
    assert right["result"] == "ready", right["reasons"]


@pytest.mark.parametrize("line", sorted(EXOS_SECRETS))
def test_exos_preview_delete_does_not_confirm_a_guessed_value(tmp_path, line):
    fields = {"op": "delete", "key": "spare", "changes": {}}
    right = exos_preview(tmp_path, EXOS_SECRETS[line], "spare", **fields)
    wrong = exos_preview(tmp_path, EXOS_SECRETS[line], "other", **fields)
    assert right == wrong
    assert right["result"] == "ready", right["reasons"]


DANGLING_POLICY = (
    'config firewall policy\n    edit 7\n        set srcintf "ghost-zone"\n        set dstintf "internal"\n'
    '        set srcaddr "ghost-host"\n        set dstaddr "all"\n        set service "ghost-svc"\n    next\nend\n'
)


@pytest.mark.parametrize("key", ["srv-web", "servers", "web-in", "grouped-host", "ghost-host", "ghost-zone",
                                 "ghost-svc", "internal", "GHOST-HOST"])
def test_fortios_create_still_refuses_names_and_references(fortios_snapshot, key):
    snapshot = replace(fortios_snapshot, "config firewall policy\n", DANGLING_POLICY + "config firewall policy\n")
    with pytest.raises(Rejected) as caught:
        plan(snapshot, key=key)
    assert caught.value.reasons in (["name %r is already used in the configuration" % key],
                                    ["key %r differs only in letter case from an existing object" % key])


def test_fortios_create_refuses_a_name_used_by_an_entry_of_another_table(fortios_snapshot):
    snapshot = replace(fortios_snapshot, "config firewall policy\n",
                       'config user local\n    edit "lab-user"\n        set passwd ENC x\n    next\nend\n'
                       "config firewall policy\n")
    rejected(snapshot, "already used", key="lab-user")


def test_fortios_delete_refusal_does_not_name_where_the_reference_is(fortios_snapshot):
    for key in ("srv-web", "grouped-host"):
        with pytest.raises(Rejected) as caught:
            plan(fortios_snapshot, op="delete", key=key, changes={})
        assert caught.value.reasons == ["object %r is referenced in the configuration" % key]


@pytest.mark.parametrize("line", ['enable igmp snooping vlan "ghost" fast-leave\n',
                                  "configure vlan ghost add ports 5 tagged\n"])
def test_exos_create_still_refuses_a_dangling_reference(exos_snapshot, line):
    snapshot = exos_snapshot + line.encode("utf-8")
    with pytest.raises(Rejected) as caught:
        exos_plan(snapshot, key="ghost")
    assert caught.value.reasons == ["name 'ghost' is already used in the configuration"]


@pytest.mark.parametrize("line", ['create account user lab-user encrypted "%s"\n',
                                  'configure snmpv3 add user lab-v3 authentication encrypted sha %s\n',
                                  "configure snmp add community readonly %s\n"])
def test_exos_plan_does_not_compare_other_secrets(exos_snapshot, line):
    for value in ("guessed", "other"):
        exos_plan(exos_snapshot + filled(line, value).encode("utf-8"), key="guessed")


def test_exos_reference_after_a_secret_still_counts(exos_snapshot):
    line = 'create netlogin local-user bob encrypted "guessed" vlan-vsa untagged %s\n'
    with pytest.raises(Rejected) as caught:
        exos_plan(exos_snapshot + filled(line, "ghost").encode("utf-8"), key="ghost")
    assert caught.value.reasons == ["name 'ghost' is already used in the configuration"]
    with pytest.raises(Rejected) as caught:
        exos_plan(exos_snapshot + filled(line, "spare").encode("utf-8"), op="delete", key="spare", changes={})
    assert caught.value.reasons == ["object 'spare' is referenced in the configuration"]
    exos_plan(exos_snapshot + filled(line, "other").encode("utf-8"), key="guessed")


@pytest.mark.parametrize("name", ["description", "encrypted", "community", "display-string"])
def test_exos_vlan_named_like_a_keyword_keeps_its_references(exos_snapshot, name):
    vlan = ('create vlan "%s"\nconfigure vlan %s tag 3001\nconfigure vlan %s add ports 6 tagged\n'
            % (name, name, name)).encode("utf-8")
    with pytest.raises(Rejected) as caught:
        exos_plan(exos_snapshot + vlan, op="delete", key=name, changes={})
    assert caught.value.reasons == ["object %r is referenced in the configuration" % name]


def test_exos_create_compares_the_object_part_of_a_description_line(exos_snapshot):
    exos_rejected(exos_snapshot, "already used", key="spare")
    exos_plan(exos_snapshot, key="unused")
    exos_plan(exos_snapshot, key="uplink")


def test_exos_delete_refusal_does_not_name_the_line(exos_snapshot):
    for key in ("DATA", "voice"):
        with pytest.raises(Rejected) as caught:
            exos_plan(exos_snapshot, op="delete", key=key, changes={})
        assert caught.value.reasons == ["object %r is referenced in the configuration" % key]


def test_refused_previews_exhaust_the_budget_of_refusals(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device, limits=dict(DEFAULT_LIMITS, rejections_per_hour=3))
    for _ in range(3):
        refused = execute.preview(runtime, "lab", request(key="srv-web"))
        assert refused["result"] == "rejected"
    assert runtime.store.rejections_since(0) == 3
    exhausted = execute.preview(runtime, "lab", request())
    assert exhausted == {"result": "rejected", "device": "lab",
                         "reasons": ["the budget of rejected requests for this hour is exhausted"]}
    assert runtime.store.rejections_since(0) == 3
    with pytest.raises(Rejected):
        execute.apply(runtime, "lab", request())
    assert device.applied_blocks == []


def test_preview_refusals_before_the_device_is_read_are_counted(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    with pytest.raises(Rejected):
        execute.preview(runtime, "lab", request(device="other"))
    assert runtime.store.rejections_since(0) == 1


def test_preview_of_an_unenrolled_device_counts_as_a_refusal(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    runtime.store.clear_enrollment("lab")
    result = execute.preview(runtime, "lab", request())
    assert result["result"] == "rejected" and result["commands"]
    assert runtime.store.rejections_since(0) == 1


def test_ready_and_known_previews_are_not_counted(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    assert execute.preview(runtime, "lab", request())["result"] == "ready"
    execute.apply(runtime, "lab", request())
    assert execute.preview(runtime, "lab", request())["result"] == "known-request"
    assert runtime.store.rejections_since(0) == 0

