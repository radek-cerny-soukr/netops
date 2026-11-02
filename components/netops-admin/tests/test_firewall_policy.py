from __future__ import annotations

import json
from importlib import resources

import pytest
from fake_fortios import FakeFortiOS as FakeFortiOS800
from test_execute import audit_lines, make_runtime, request, steps

from netops_admin import execute, profiles
from netops_admin.config import _device
from netops_admin.errors import Rejected



class FakeFortiOS(FakeFortiOS800):
    firmware = ("7.6.8", "3744")


BASE = {"srcintf": ["port1"], "dstintf": ["port2"], "srcaddr": ["all"], "dstaddr": ["srv-web"],
        "service": ["HTTP"], "schedule": "always", "action": "accept", "status": "disable"}


def policy(**fields):
    fields.setdefault("table", "firewall policy")
    fields.setdefault("key", "9001")
    fields.setdefault("op", "create")
    fields.setdefault("changes", dict(BASE))
    return request(**fields)


def runtime(tmp_path, device, **fields):
    fields.setdefault("opt_in", ("firewall policy",))
    fields.setdefault("protected", {"system interface": ["wan1"]})
    return make_runtime(tmp_path, device, **fields)


def rejected(tmp_path, device, req, **fields):
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime(tmp_path, device, **fields), "lab", req)
    return " ".join(caught.value.reasons)


def test_profile_loads_and_is_provisional():
    profile = profiles.find_profile("fortios", "firewall policy", "7.6.8 build3744")
    assert profile is not None and profile.provisional and profile.exact_versions
    assert profile.undo_ops == ("delete",) and profile.create_position == "last"
    assert profile.attributes["logtraffic"].default == "utm"
    assert profile.attributes["status"].default == "enable" and profile.attributes["action"].default == "deny"
    for retired in ("8.0.0 build0167", "7.6.7 build3704", "8.0.1 build0200", "8.0.2 build0250", "8.0.3 build0300"):
        with pytest.raises(Rejected):
            profiles.find_profile("fortios", "firewall policy", retired)


def test_opt_in_off_by_default(tmp_path):
    device = FakeFortiOS()
    assert "not enabled" in rejected(tmp_path, device, policy(), opt_in=())
    assert "9001" not in device.policies


def test_create_disabled_then_enable_then_undo(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    record = execute.apply(rt, "lab", policy())
    assert record["result"] == "confirmed"
    assert device.policies["9001"]["status"] == "disable"
    assert list(device.policies)[-1] == "9001"
    assert not device.stitches
    record = execute.apply(rt, "lab", policy(op="update", changes={"status": "enable"}, request_id="req-enable-1"))
    assert record["result"] == "confirmed" and device.policies["9001"]["status"] == "enable"
    back = execute.undo(rt, record["change_id"], "investigated")
    assert back["result"] == "confirmed" and device.policies["9001"]["status"] == "disable"


def test_create_requires_status_disable(tmp_path):
    device = FakeFortiOS()
    changes = dict(BASE)
    del changes["status"]
    assert "create needs status" in rejected(tmp_path, device, policy(changes=changes))
    changes["status"] = "enable"
    assert "create needs status disable" in rejected(tmp_path, device, policy(changes=changes, request_id="req-bad-2"))
    assert "9001" not in device.policies


def test_create_not_placed_last_is_detected(tmp_path):
    device = FakeFortiOS()
    device.policy_front = True
    record_or_error = None
    try:
        record_or_error = execute.apply(runtime(tmp_path, device), "lab", policy())["result"]
    except Rejected as error:
        record_or_error = " ".join(error.reasons)
    assert record_or_error != "confirmed"


def test_policy_id_beyond_maximum_is_refused(tmp_path):
    device = FakeFortiOS()
    assert "exceeds" in rejected(tmp_path, device, policy(key="4294967295"))


def test_missing_object_is_refused(tmp_path):
    device = FakeFortiOS()
    changes = dict(BASE, dstaddr=["no-such-object"])
    assert "missing from the visible snapshot" in rejected(tmp_path, device, policy(changes=changes))
    changes = dict(BASE, srcintf=["no-such-port"])
    assert "missing from the visible snapshot" in rejected(tmp_path, device, policy(changes=changes, request_id="req-bad-3"))


def test_protected_management_path_is_refused(tmp_path):
    device = FakeFortiOS()
    changes = dict(BASE, srcintf=["wan1"])
    assert "protected object 'wan1'" in rejected(tmp_path, device, policy(changes=changes))
    changes = dict(BASE, srcintf=["any"])
    assert "management path" in rejected(tmp_path, device, policy(changes=changes, request_id="req-bad-4"))


def test_protected_interface_missing_from_snapshot_is_refused(tmp_path):
    device = FakeFortiOS()
    reasons = rejected(tmp_path, device, policy(), protected={"system interface": ["ghost"]})
    assert "protected interface ghost is missing" in reasons


def test_inverse_over_script_limit_is_refused(tmp_path, monkeypatch):
    from netops_admin import fortios
    monkeypatch.setattr(fortios, "SAFEGUARD_SCRIPT_LIMIT", 10)
    device = FakeFortiOS()
    assert "safeguard script limit" in rejected(tmp_path, device, policy())


def test_status_only_update_is_isolated(tmp_path):
    device = FakeFortiOS()
    device.policies["1"].update(srcintf="port1", dstintf="port2", srcaddr="all", service="HTTP",
                                schedule="always", action="accept", status="disable")
    rt = runtime(tmp_path, device)
    record = execute.apply(rt, "lab", policy(op="update", key="1", changes={"status": "enable"}))
    assert record["result"] == "confirmed" and device.policies["1"]["status"] == "enable"


def test_update_other_attribute_runs_normal_path(tmp_path):
    device = FakeFortiOS()
    device.policies["1"].update(srcintf="port1", dstintf="port2", srcaddr="all", service="HTTP",
                                schedule="always", action="accept", status="disable")
    rt = runtime(tmp_path, device)
    record = execute.apply(rt, "lab", policy(op="update", key="1", changes={"comments": "note"}))
    assert record["result"] == "confirmed" and device.policies["1"]["comments"] == "note"


def test_delete_is_not_offered_as_request(tmp_path):
    device = FakeFortiOS()
    reasons = rejected(tmp_path, device, policy(op="delete", key="1", changes={}))
    assert reasons


def test_attribute_name_must_match_whole(tmp_path):
    device = FakeFortiOS()
    changes = dict(BASE)
    changes["status\n"] = "enable"
    with pytest.raises(Rejected):
        policy(changes=changes)


def test_audit_never_holds_secret(tmp_path):
    device = FakeFortiOS()
    execute.apply(runtime(tmp_path, device), "lab", policy())
    assert "SECRET-MARKER" not in json.dumps(audit_lines(tmp_path))
    assert steps({"steps": [{"step": "x"}]}) == ["x"]


def test_opt_in_config_validation():
    data = {"platform": "fortios", "address": "192.0.2.1", "port": 22,
            "host_key_fingerprint": "SHA256:" + "A" * 43, "vault": "/x", "credential": "rw",
            "check_credential": "ro", "opt_in": ["firewall policy"]}
    with pytest.raises(Rejected) as caught:
        _device("lab", dict(data))
    assert "protected system interface" in " ".join(caught.value.reasons)
    for bad in (["firewall address"], ["firewall policy", "firewall policy"], "firewall policy"):
        with pytest.raises(Rejected):
            _device("lab", dict(data, opt_in=bad, protected={"system interface": ["wan1"]}))
    ok = _device("lab", dict(data, protected={"system interface": ["wan1"]}))
    assert ok.opt_in == ("firewall policy",)
    assert _device("lab", {k: v for k, v in data.items() if k != "opt_in"}).opt_in == ()


def test_undo_of_create_deletes_even_without_opt_in(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    first = execute.apply(rt, "lab", policy())
    rt.config.devices["lab"] = __import__("dataclasses").replace(rt.config.devices["lab"], opt_in=())
    from enrollment_helpers import certify
    certify(rt, device, "lab")
    back = execute.undo(rt, first["change_id"], "investigated")
    assert back["result"] == "confirmed" and "9001" not in device.policies


def test_undo_of_comment_update_restores_state(tmp_path):
    device = FakeFortiOS()
    device.policies["1"].update(srcintf="port1", dstintf="port2", srcaddr="all", service="HTTP",
                                schedule="always", action="accept", status="disable")
    rt = runtime(tmp_path, device)
    first = execute.apply(rt, "lab", policy(op="update", key="1", changes={"comments": "note"}))
    back = execute.undo(rt, first["change_id"], "investigated")
    assert back["result"] == "confirmed" and "comments" not in device.policies["1"]


def test_undo_of_action_change_returns_default_for_unset_attribute(tmp_path):
    device = FakeFortiOS()
    device.policies["1"].update(srcintf="port1", dstintf="port2", srcaddr="all", service="HTTP",
                                schedule="always", status="disable")
    rt = runtime(tmp_path, device)
    first = execute.apply(rt, "lab", policy(op="update", key="1", changes={"action": "accept"}))
    assert device.policies["1"]["action"] == "accept"
    back = execute.undo(rt, first["change_id"], "investigated")
    assert back["result"] == "confirmed" and device.policies["1"].get("action", "deny") == "deny"


def test_19a_lost_connection_after_the_change_ends_unknown(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    device.unreachable_after_apply = lambda lines: lines[0] == "config firewall policy"
    record = execute.apply(rt, "lab", policy())
    assert record["result"] == "unknown"
    names = steps(record)
    assert names.index("safeguard_verified") < names.index("change_start") < names.index("change_applied")
    assert "safeguard_not_verified" not in names
    assert "postcheck_failed" in names and "revert_unverified" in names
    assert [block[0] for block in device.applied_blocks[-2:]] == ["config system automation-action", "config firewall policy"]
    assert not rt.store.running("lab")
    assert execute.recover(rt, "lab") == []
    device.unreachable_after_apply = None
    device.unreachable = False
    with pytest.raises(Rejected):
        execute.apply(rt, "lab", policy(key="9002", request_id="req-next-1"))
    stitch = next(iter(device.stitches))
    assert stitch.startswith("netops-sg-")


def test_19a_doctor_lists_the_leftover_safeguard(tmp_path):
    from netops_admin import readiness
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    device.unreachable_after_apply = lambda lines: lines[0] == "config firewall policy"
    execute.apply(rt, "lab", policy())
    device.unreachable_after_apply = None
    device.unreachable = False
    report = readiness.doctor(rt, "lab")
    leftover = {item["check"]: item for item in report["checks"]}["leftover safeguards"]
    assert leftover["status"] != readiness.OK and "netops-sg-" in leftover["detail"]


def test_19b_failed_postcheck_read_is_reverted_by_the_safeguard(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)

    def arm(fake, lines):
        if lines[0] == "config firewall policy":
            fake.fail_next = 1

    device.on_apply = arm
    record = execute.apply(rt, "lab", policy())
    names = steps(record)
    assert record["result"] == "reverted"
    assert "postcheck_failed" in names and "revert_unverified" not in names
    assert "9001" not in device.policies and not device.stitches
    device.on_apply = None
    assert execute.apply(rt, "lab", policy(request_id="req-next-2"))["result"] == "confirmed"


def test_enrollment_from_an_older_release_does_not_fit(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    certificate = rt.store.enrollment("lab")
    rt.store.save_enrollment("lab", dict(certificate, binding="0" * len(certificate["binding"])))
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab", request())
    assert "enroll self-test is required" in " ".join(caught.value.reasons)
    from enrollment_helpers import certify
    certify(rt, device, "lab")
    assert execute.apply(rt, "lab", request())["result"] == "confirmed"


def test_clean_install_needs_enrollment(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    rt.store.clear_enrollment("lab")
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab", policy())
    assert "enroll self-test is required" in " ".join(caught.value.reasons)
    from enrollment_helpers import certify
    certify(rt, device, "lab")
    assert execute.apply(rt, "lab", policy())["result"] == "confirmed"


def test_running_operation_makes_doctor_refuse(tmp_path):
    from netops_admin import readiness
    device = FakeFortiOS()
    blocks = []

    def crash(fake, lines):
        blocks.append(lines)
        if len(blocks) == 2:
            fake._run(lines)
            raise KeyboardInterrupt

    device.on_apply = crash
    rt = runtime(tmp_path, device)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(rt, "lab", policy())
    device.on_apply = None
    report = readiness.doctor(rt, "lab")
    state = {item["check"]: item for item in report["checks"]}["device state"]
    assert state["status"] != readiness.OK
    assert "an unfinished operation exists; run recover first" in state["detail"]
    assert report["ready"] is False
    settled = execute.recover(rt, "lab")
    assert [item["result"] for item in settled] == ["reverted"]
    assert "9001" not in device.policies


def test_19a_cleanup_removes_only_its_own_safeguard(tmp_path):
    from netops_admin import exec_fortios, fortios, readiness
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    device.unreachable_after_apply = lambda lines: lines[0] == "config firewall policy"
    record = execute.apply(rt, "lab", policy())
    device.unreachable_after_apply = None
    device.unreachable = False
    foreign = "netops-sg-" + "f" * 12
    device.stitches[foreign + "-s"] = {"trigger": foreign + "-t", "action": foreign + "-a"}
    device.triggers[foreign + "-t"] = "2099-01-01 00:00:00"
    device.actions[foreign + "-a"] = "config firewall policy\nend"
    own = fortios.safeguard_names(record["change_id"])
    assert own["stitch"] in device.stitches
    assert exec_fortios.remove_remaining(device, record, exec_fortios.prompt_spec(device.hostname))
    assert own["stitch"] not in device.stitches and own["trigger"] not in device.triggers
    assert own["action"] not in device.actions
    assert foreign + "-s" in device.stitches and foreign + "-t" in device.triggers and foreign + "-a" in device.actions
    leftover = {item["check"]: item for item in readiness.doctor(rt, "lab")["checks"]}["leftover safeguards"]
    assert foreign in leftover["detail"] and own["stitch"] not in leftover["detail"]
    assert execute.unblock(rt, "lab", "investigated")
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab", policy(key="9002", request_id="req-next-3"))
    assert "a safeguard of an earlier operation is still installed" in " ".join(caught.value.reasons)
    for table in (device.stitches, device.triggers, device.actions):
        for name in [name for name in table if name.startswith(foreign)]:
            del table[name]
    assert execute.apply(rt, "lab", policy(key="9002", request_id="req-next-4"))["result"] == "confirmed"


def test_binding_changes_with_the_content_of_a_profile(tmp_path, monkeypatch):
    import shutil
    from importlib import resources
    from netops_admin import enrollment
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    configured = rt.config.devices["lab"]
    before = enrollment.binding(configured, {}, "fw", rt.config)
    package = tmp_path / "pkg"
    shutil.copytree(resources.files("netops_admin") / "profiles", package / "profiles")
    target = package / "profiles" / "fortios-firewall-policy.json"
    target.write_text(target.read_text() + "\n")
    monkeypatch.setattr(enrollment.resources, "files", lambda name: package)
    assert enrollment.binding(configured, {}, "fw", rt.config) != before


GROUPS = ["config firewall addrgrp", '    edit "web-group"', "        set uuid 00000000-0000-4000-8000-0000000000c1",
          '        set member "inner-group"', "    next", '    edit "inner-group"',
          "        set uuid 00000000-0000-4000-8000-0000000000c2", '        set member "srv-web"', "    next", "end"]


@pytest.mark.parametrize("field", ["srcaddr", "dstaddr"])
def test_policy_reaching_a_protected_address_through_a_group_is_refused(tmp_path, field):
    device = FakeFortiOS()
    device.snapshot_extra = list(GROUPS)
    changes = dict(BASE, dstaddr=["spare-host"])
    changes[field] = ["web-group"]
    reasons = rejected(tmp_path, device, policy(changes=changes),
                       protected={"system interface": ["wan1"], "firewall address": ["srv-web"]})
    assert "protected object 'srv-web'" in reasons
    assert "9001" not in device.policies


def test_policy_on_a_group_without_protected_members_is_planned(tmp_path):
    device = FakeFortiOS()
    device.snapshot_extra = list(GROUPS)
    rt = runtime(tmp_path, device, protected={"system interface": ["wan1"], "firewall address": ["spare-host"]})
    record = execute.apply(rt, "lab", policy(changes=dict(BASE, dstaddr=["web-group"])))
    assert record["result"] == "confirmed" and device.policies["9001"]["dstaddr"] == "web-group"


@pytest.mark.parametrize("firmware", [("8.0.1", "0245"), ("8.0.0", "0167"), ("7.6.7", "3704")])
def test_policy_runs_only_on_the_measured_builds(tmp_path, firmware):
    device = type("Other", (FakeFortiOS800,), {"firmware": firmware})()
    assert "not measured on firmware" in rejected(tmp_path, device, policy())
    assert "9001" not in device.policies and not device.stitches



def test_deny_without_logtraffic_is_refused_before_any_change(tmp_path):
    device = FakeFortiOS()
    assert "action deny needs logtraffic in the same request" in rejected(tmp_path, device, policy(changes=dict(BASE, action="deny")))
    assert "9001" not in device.policies and not device.stitches


def test_deny_with_logtraffic_disable_is_refused_by_the_audit(tmp_path):
    device = FakeFortiOS()
    reasons = rejected(tmp_path, device, policy(changes=dict(BASE, action="deny", logtraffic="disable")))
    assert "fortios.policy.logging-disabled" in reasons
    assert "9001" not in device.policies and not device.stitches


def test_deny_with_logtraffic_all_is_confirmed(tmp_path):
    device = FakeFortiOS()
    record = execute.apply(runtime(tmp_path, device), "lab", policy(changes=dict(BASE, action="deny", logtraffic="all")))
    assert record["result"] == "confirmed"
    assert device.policies["9001"]["action"] == "deny" and device.policies["9001"]["logtraffic"] == "all"


def test_update_to_deny_needs_logtraffic(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    assert execute.apply(rt, "lab", policy())["result"] == "confirmed"
    reasons = rejected(tmp_path, device, policy(op="update", changes={"action": "deny"}, request_id="req-deny-3"))
    assert "action deny needs logtraffic in the same request" in reasons
    record = execute.apply(rt, "lab", policy(op="update", changes={"action": "deny", "logtraffic": "all"},
                                              request_id="req-deny-4"))
    assert record["result"] == "confirmed" and device.policies["9001"]["logtraffic"] == "all"


def test_value_requires_must_name_a_later_attribute():
    data = json.loads((resources.files("netops_admin") / "profiles" / "fortios-firewall-policy.json").read_text())
    data["value_requires"] = {"logtraffic": {"all": ["action"]}}
    with pytest.raises(profiles.ProfileError, match="value_requires"):
        profiles.parse_profile(data)
    data["value_requires"] = {"action": {"deny": ["logtraffic"]}}
    assert profiles.parse_profile(data).value_requires == {"action": {"deny": ("logtraffic",)}}
