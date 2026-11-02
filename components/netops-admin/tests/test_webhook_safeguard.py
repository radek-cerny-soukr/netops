from __future__ import annotations

import json
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fake_fortios import FakeFortiOS
from fake_webhook import FakeFortiOSWebhook
from test_access import Shell, device_access
from test_execute import make_runtime, request, steps

from netops_admin import access, audit_gate, enrollment, exec_fortios, execute, fortios, profiles, readiness
from netops_admin.errors import Rejected

BASE = {"srcintf": ["port1"], "dstintf": ["port2"], "srcaddr": ["all"], "dstaddr": ["srv-web"],
        "service": ["HTTP"], "schedule": "always", "action": "accept", "status": "disable"}


class Fake768(FakeFortiOS):
    firmware = ("7.6.8", "3744")


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


def own_objects(device):
    names = [name for part in ("webhooks", "api_users", "accprofiles") for name in getattr(device, part, {})]
    names += list(device.stitches) + list(device.triggers) + list(device.actions)
    return [name for name in names if name.startswith("netops-sg-")]


def lines(device):
    return [line for block in device.applied_blocks for line in block]


def stored_text(tmp_path):
    return "".join(path.read_text(errors="replace") for path in sorted(tmp_path.rglob("*")) if path.is_file())


def check_failure_after_change(device):
    def hook(fake, block):
        if block[0] == "config firewall policy":
            fake.check_unreadable = True
    device.on_apply = hook


@pytest.mark.parametrize("firmware,expected", [
    ("7.6.8 build3744", False), ("8.0.0 build0167", False), ("8.0.1 build0185", True),
    ("8.0.2 build0251", True), ("8.2.0 build0001", True), (None, False), ("8.0.x", False),
])
def test_mechanism_follows_firmware(firmware, expected):
    assert fortios.webhook_firmware(firmware) is expected


def test_profiles_list_the_webhook_build():
    policy_profile = profiles.find_profile("fortios", "firewall policy", "8.0.2 build0251")
    assert policy_profile.provisional
    assert "webhook" in policy_profile.rollback_evidence
    assert profiles.find_profile("fortios", "firewall address", "8.0.2 build0251") is not None
    for table in ("firewall addrgrp", "system dhcp server/reserved-address"):
        with pytest.raises(Rejected):
            profiles.find_profile("fortios", table, "8.0.2 build0251")
    with pytest.raises(Rejected):
        profiles.find_profile("fortios", "firewall policy", "8.0.1 build0185")


def test_7_6_8_keeps_the_cli_script_safeguard(tmp_path):
    device = Fake768()
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    assert record["result"] == "confirmed"
    sent = lines(device)
    assert "set action-type cli-script" in sent
    assert not any("webhook" in line or "api-user" in line or "accprofile" in line for line in sent)


def test_create_update_undo_are_confirmed_without_leftovers(tmp_path):
    device = FakeFortiOSWebhook()
    rt = runtime(tmp_path, device)
    record = execute.apply(rt, "lab", policy())
    assert record["result"] == "confirmed" and device.policies["9001"]["status"] == "disable"
    sent = lines(device)
    assert "set action-type webhook" in sent and "set action-type cli-script" not in sent
    assert "set method delete" in sent
    assert own_objects(device) == []
    assert device.calls == []
    record = execute.apply(rt, "lab", policy(op="update", changes={"status": "enable"}, request_id="req-enable-1"))
    assert record["result"] == "confirmed" and device.policies["9001"]["status"] == "enable"
    back = execute.undo(rt, record["change_id"], "investigated")
    assert back["result"] == "confirmed" and device.policies["9001"]["status"] == "disable"
    assert own_objects(device) == [] and len(device.issued) == 3 and device.calls == []


def test_firing_reverts_a_create_with_delete(tmp_path):
    device = FakeFortiOSWebhook()
    check_failure_after_change(device)
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    assert record["result"] == "reverted"
    assert "9001" not in device.policies
    assert device.calls == [("delete", "api/v2/cmdb/firewall/policy/9001", 200)]
    assert own_objects(device) == []


def test_firing_reverts_an_update_with_put(tmp_path):
    device = FakeFortiOSWebhook()
    device.policies["1"].update(srcintf="port1", dstintf="port2", srcaddr="all", service="HTTP",
                                schedule="always", action="accept", status="disable")
    check_failure_after_change(device)
    record = execute.apply(runtime(tmp_path, device), "lab",
                           policy(op="update", key="1", changes={"comments": "note", "status": "enable"}))
    assert record["result"] == "reverted"
    assert device.calls == [("put", "api/v2/cmdb/firewall/policy/1", 200)]
    assert device.policies["1"]["status"] == "disable" and "comments" not in device.policies["1"]
    assert own_objects(device) == []


def test_firing_reverts_an_undo_of_create_with_post(tmp_path):
    device = FakeFortiOSWebhook()
    rt = runtime(tmp_path, device)
    first = execute.apply(rt, "lab", policy())
    assert first["result"] == "confirmed"
    check_failure_after_change(device)
    back = execute.undo(rt, first["change_id"], "investigated")
    assert back["result"] == "reverted"
    assert device.calls == [("post", "api/v2/cmdb/firewall/policy", 200)]
    assert list(device.policies)[-1] == "9001" and device.policies["9001"]["srcintf"] == "port1"
    assert own_objects(device) == []


def test_address_enrollment_probe_style_create_reverts(tmp_path):
    device = FakeFortiOSWebhook()
    check = lambda fake, block: setattr(fake, "check_unreadable", block[0] == "config firewall address")
    device.on_apply = check
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] == "reverted" and "new-host" not in device.addresses
    assert device.calls == [("delete", "api/v2/cmdb/firewall/address/new-host", 200)]


def test_token_never_reaches_audit_state_record_or_preview(tmp_path):
    device = FakeFortiOSWebhook()
    rt = runtime(tmp_path, device)
    preview = execute.preview(rt, "lab", policy(key="9002", request_id="req-preview-1"))
    confirmed = execute.apply(rt, "lab", policy())
    check_failure_after_change(device)
    reverted = execute.apply(rt, "lab", policy(key="9003", request_id="req-reverted-1"))
    assert confirmed["result"] == "confirmed" and reverted["result"] == "reverted"
    assert len(device.issued) == 2
    texts = [stored_text(tmp_path), json.dumps(preview), json.dumps(confirmed), json.dumps(reverted)]
    for token in device.issued:
        assert all(token not in text for text in texts)
    assert "Bearer" not in stored_text(tmp_path)


@pytest.mark.parametrize("change,expected", [
    (lambda d, f: f.update(address="fw-lab.example"), "device address as an IPv4 address"),
    (lambda d, f: setattr(d, "interface_lines", {}), "no interface holds that address"),
    (lambda d, f: d.interface_lines.update(port1=["set ip 192.0.2.1 255.255.255.0", "set allowaccess ping ssh"]),
     "needs https in allowaccess of interface port1"),
    (lambda d, f: setattr(d, "credential", SimpleNamespace(login="netops-rw", kind="ssh-key")),
     "needs a password write credential"),
    (lambda d, f: d.api_users.update({"netops-sg-0123456789ab-u": {"trusthost": []}}),
     "a safeguard of an earlier operation is still installed: netops-sg-0123456789ab-u"),
    (lambda d, f: d.accprofiles.update({"netops-sg-0123456789ab-p": {"fwgrp": "read-write"}}),
     "a safeguard of an earlier operation is still installed: netops-sg-0123456789ab-p"),
    (lambda d, f: d.write_admins.update({"netops-rw": "netops-rw-prof"}),
     "needs the write account netops-rw with access profile super_admin on FortiOS 8.0.1 and later"),
    (lambda d, f: d.write_admins.clear(), "cannot find the write account netops-rw in system admin; on FortiOS"
     " 8.0.1 and later it needs access profile super_admin"),
    (lambda d, f: setattr(d, "admin_sport", 70000), "the HTTPS administration port cannot be read"),
])
def test_preflight_refuses_before_any_write(tmp_path, change, expected):
    device = FakeFortiOSWebhook()
    fields = {}
    change(device, fields)
    reasons = rejected(tmp_path, device, policy(), **fields)
    assert expected in reasons
    assert device.applied_blocks == [] and device.issued == [] and "9001" not in device.policies


def test_a_super_admin_write_account_passes_the_execute_check(tmp_path):
    device = FakeFortiOSWebhook()
    device.write_admins = {"netops-rw": "super_admin"}
    assert execute.apply(runtime(tmp_path, device), "lab", policy())["result"] == "confirmed"


def test_doctor_accepts_a_super_admin_write_account(tmp_path):
    device = FakeFortiOSWebhook()
    device.write_admins = {"netops-rw": "super_admin"}
    assert webhook_check(tmp_path, device)["status"] == readiness.OK


def test_a_restricted_write_account_is_refused_by_enrollment_before_any_write(tmp_path):
    device = FakeFortiOSWebhook()
    device.write_admins = {"netops-rw": "netops-rw-prof"}
    rt = make_runtime(tmp_path, device)
    rt.store.clear_enrollment("lab")
    status = tmp_path / "export.json"
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 0}))
    rt.config = replace(rt.config, export_status_file=str(status))
    rt.notifier = lambda record: "sent"
    with pytest.raises(Rejected) as caught:
        enrollment.run(rt, "lab", "192.0.2.254/32")
    assert "needs the write account netops-rw with access profile super_admin" in " ".join(caught.value.reasons)
    assert device.applied_blocks == [] and device.issued == []


def test_a_refused_installation_line_reaches_the_operation_steps(tmp_path):
    device = FakeFortiOSWebhook()

    def refuse(fake, block):
        if block[0] == "config system accprofile":
            raise access.AccessError('line 13 (config system accprofile, edit "netops-sg-x-p") was refused by the'
                                     " device: object set operator error, -672 discard the setting", 12)
    device.on_apply = refuse
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    detail = [step["detail"] for step in record["steps"] if step["step"] == "safeguard_not_verified"][0]
    assert record["result"] == "reverted"
    assert detail.startswith("safeguard installation failed (AccessError: line 13 (config system accprofile")
    assert "-672 discard the setting" in detail


def test_a_refused_line_with_the_token_does_not_carry_the_token(tmp_path):
    device = FakeFortiOSWebhook()

    def refuse(fake, block):
        if block[0] == "config system automation-action":
            raise access.AccessError("line 17 (config system automation-action, edit \"netops-sg-x-a\", edit 1) was"
                                     " refused by the device: command parse error before 'Bearer %s'"
                                     % fake.issued[-1], 16)
    device.on_apply = refuse
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    detail = [step["detail"] for step in record["steps"] if step["step"] == "safeguard_not_verified"][0]
    assert record["result"] == "reverted" and len(device.issued) == 1
    assert detail.startswith("safeguard installation failed (AccessError: line 17 (config system automation-action")
    assert "command parse error before 'Bearer <token>'" in detail
    for text in (detail, stored_text(tmp_path), json.dumps(record)):
        assert device.issued[0] not in text


def test_the_installation_reads_the_port_before_it_creates_the_api_user(tmp_path, monkeypatch):
    device = FakeFortiOSWebhook()
    checked = exec_fortios.plan_prechecks

    def port_lost_after_preflight(*args, **kwargs):
        reasons = checked(*args, **kwargs)
        device.admin_sport = 70000
        return reasons
    monkeypatch.setattr(exec_fortios, "plan_prechecks", port_lost_after_preflight)
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    assert record["result"] == "reverted" and "safeguard_not_verified" in steps(record)
    assert device.issued == [] and not any(line.startswith('edit "netops-sg-') for line in lines(device))
    assert "9001" not in device.policies and own_objects(device) == []


def test_preflight_does_not_apply_to_cli_script_firmware(tmp_path):
    device = Fake768()
    record = execute.apply(runtime(tmp_path, device, address="fw-lab.example"), "lab", policy())
    assert record["result"] == "confirmed"


def test_rest_inverse_shapes_and_limits():
    policy_profile = profiles.find_profile("fortios", "firewall policy", "8.0.2 build0251")
    inverse = fortios.render_create(policy_profile, "7", {"srcintf": "port1 port3", "schedule": "always",
                                                          "comments": 'say "hi"'})
    request_ = fortios.rest_inverse(policy_profile, "delete", "7", inverse, "192.0.2.1")
    assert request_["method"] == "post" and request_["uri"] == "192.0.2.1/api/v2/cmdb/firewall/policy"
    assert json.loads(request_["body"]) == {"policyid": 7, "srcintf": [{"name": "port1"}, {"name": "port3"}],
                                            "schedule": "always", "comments": 'say "hi"'}
    update = fortios.render_update(policy_profile, "7", {"comments": "old"}, ["action", "name"])
    request_ = fortios.rest_inverse(policy_profile, "update", "7", update, "192.0.2.1")
    assert request_["method"] == "put" and request_["uri"].endswith("/firewall/policy/7")
    assert json.loads(request_["body"]) == {"comments": "old", "action": "deny", "name": ""}
    address = profiles.find_profile("fortios", "firewall address", "8.0.2 build0251")
    request_ = fortios.rest_inverse(address, "create", "a b/c", fortios.render_delete(address, "a b/c"), "192.0.2.1")
    assert request_ == {"method": "delete", "uri": "192.0.2.1/api/v2/cmdb/firewall/address/a%20b%2Fc", "body": ""}
    big = fortios.render_update(policy_profile, "7", {"comments": "x" * 1100}, [])
    with pytest.raises(Rejected) as caught:
        fortios.rest_inverse(policy_profile, "update", "7", big, "192.0.2.1")
    assert "request body limit" in " ".join(caught.value.reasons)
    dhcp = profiles.load_profiles()[("fortios", "system dhcp server/reserved-address")]
    with pytest.raises(Rejected) as caught:
        fortios.rest_inverse(dhcp, "create", "1:2", [], "192.0.2.1")
    assert "no REST inverse for table system dhcp server/reserved-address" in " ".join(caught.value.reasons)


def step_text(step):
    return step if isinstance(step, str) else step[1]


def test_rendered_identity_is_limited():
    text = "\n".join(step_text(step) for step in fortios.render_webhook_identity("0123456789abcdef", "192.0.2.1"))
    assert "set fwgrp read-write" in text and "set ipv4-trusthost 192.0.2.1 255.255.255.255" in text
    assert "vdom" not in text and text.count("read-write") == 1
    assert all("set %s none" % group in text for group in fortios.ACCPROFILE_NONE)


def test_recover_after_interruption_lets_the_webhook_fire_and_revokes(tmp_path):
    device = FakeFortiOSWebhook()
    blocks = []

    def crash(fake, block):
        blocks.append(block)
        if block[0] == "config firewall policy":
            fake._run(block)
            raise KeyboardInterrupt

    device.on_apply = crash
    rt = runtime(tmp_path, device)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(rt, "lab", policy())
    device.on_apply = None
    assert device.api_users and device.webhooks
    settled = execute.recover(rt, "lab")
    assert [item["result"] for item in settled] == ["reverted"]
    assert "9001" not in device.policies and own_objects(device) == []


def test_the_api_user_save_and_delete_answer_the_password_prompt():
    identity = fortios.render_webhook_identity("0123456789abcdef", "192.0.2.1")
    start = identity.index("config system api-user")
    assert identity[start:][-2:] == [("password", "next"), "end"]
    assert sum(isinstance(step, tuple) for step in identity) == 1
    assert fortios.render_webhook_removal("0123456789abcdef", ("user", "profile")) == [
        "config system api-user", ("password", 'delete "netops-sg-0123456789ab-u"'), "end",
        "config system accprofile", 'delete "netops-sg-0123456789ab-p"', "end"]


def test_recover_removes_the_leftover_of_a_safeguard_that_was_not_verified(tmp_path):
    device = FakeFortiOSWebhook()

    def partial(fake, block):
        if any(line.startswith("delete ") for line in block):
            raise access.AccessError("interactive session failed after 1 lines: the session ended", 1)
        if block[0] == "config system accprofile":
            end = block.index("end") + 1
            fake._run(block[:end])
            raise access.AccessError("interactive session failed after %d lines: the session ended" % end, end)

    device.on_apply = partial
    rt = runtime(tmp_path, device)
    record = execute.apply(rt, "lab", policy())
    assert (record["result"], record["reason"]) == ("unknown", "safeguard not verified")
    assert list(device.accprofiles) == ["netops-sg-%s-p" % record["change_id"][:12]]
    assert rt.store.blocked("lab")["change_id"] == record["change_id"]
    device.on_apply = None
    settled = execute.recover(rt, "lab")
    assert [item["change_id"] for item in settled] == [record["change_id"]]
    assert steps(settled[0])[-1] == "safeguard_removed" and settled[0]["result"] == "unknown"
    assert own_objects(device) == [] and "9001" not in device.policies
    assert rt.store.blocked("lab")["change_id"] == record["change_id"]
    assert execute.recover(rt, "lab") == []


def test_recover_with_a_disarmed_stitch_deletes_api_user_and_profile(tmp_path):
    device = FakeFortiOSWebhook()

    def crash(fake, block):
        if block[0] == "config firewall policy":
            fake._run(block)
            fake.stitches.clear()
            raise KeyboardInterrupt

    device.on_apply = crash
    rt = runtime(tmp_path, device)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(rt, "lab", policy())
    device.on_apply = None
    assert device.api_users and device.accprofiles
    settled = execute.recover(rt, "lab")
    assert settled and "safeguard_removed" in steps(settled[0])
    assert device.api_users == {} and device.accprofiles == {} and own_objects(device) == []


def test_firing_not_proven_revokes_the_token_and_keeps_the_stitch(tmp_path):
    device = FakeFortiOSWebhook()
    device.webhook_broken = True
    check_failure_after_change(device)
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    assert record["result"] == "unknown"
    names = steps(record)
    assert names[-2:] == ["safeguard_kept", "safeguard_token_revoked"]
    assert device.api_users == {} and device.accprofiles == {}
    assert device.stitches and device.triggers and device.webhooks
    assert device.calls == [("delete", "api/v2/cmdb/firewall/policy/9001", 401)]


def test_firing_not_proven_reports_an_unproven_revocation(tmp_path, monkeypatch):
    device = FakeFortiOSWebhook()
    device.webhook_broken = True
    check_failure_after_change(device)
    monkeypatch.setattr(fortios, "webhook_absent", lambda *args, **kwargs: False)
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    assert record["result"] == "unknown"
    assert "safeguard_token_revoke_unverified" in steps(record)


@pytest.mark.parametrize("fake", [Fake768, FakeFortiOSWebhook])
def test_undo_of_create_refused_when_the_policy_is_no_longer_last(tmp_path, fake):
    device = fake()
    rt = runtime(tmp_path, device)
    first = execute.apply(rt, "lab", policy())
    assert first["result"] == "confirmed"
    device.policies["9002"] = {"uuid": device._uuid(), "srcintf": "port1", "dstintf": "port2", "srcaddr": "all",
                               "dstaddr": "srv-web", "service": "HTTP", "schedule": "always", "status": "disable"}
    with pytest.raises(Rejected) as caught:
        execute.undo(rt, first["change_id"], "investigated")
    assert "no longer the last policy" in " ".join(caught.value.reasons)
    assert "9001" in device.policies


def test_tampered_header_is_not_verified_and_everything_is_removed(tmp_path):
    device = FakeFortiOSWebhook()
    device.header_override = "Bearer someone-else"
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    assert record["result"] == "reverted" and "safeguard_not_verified" in steps(record)
    assert "9001" not in device.policies and own_objects(device) == []


def test_missing_api_key_fails_safely(tmp_path):
    device = FakeFortiOSWebhook()
    device.key_answer = "Please enter current administrator password:\nCommand fail. Return code -1\n"
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    assert record["result"] == "reverted" and "safeguard_not_verified" in steps(record)
    assert "9001" not in device.policies and own_objects(device) == []
    assert not any("automation-action" in block[0] for block in device.applied_blocks)


def test_api_key_parsing():
    assert fortios.api_key("x\r\nNew API key: abc123\r\n\r\nNOTE: text\r\n") == "abc123"
    for text in ("", "New API key:\n", "New API key: a\nNew API key: b\n", "token abc123\n"):
        with pytest.raises(Rejected) as caught:
            fortios.api_key(text)
        assert "abc" not in " ".join(caught.value.reasons)


def credential(kind="password"):
    return SimpleNamespace(login="netops-rw", kind=kind, use=lambda: "pw-value")


def test_device_access_answers_the_password_prompt_once():
    shell = Shell([b"fw-lab $ ",
                   b'execute api-user generate-key "netops-sg-x-u"\r\nPlease enter current administrator password:',
                   b"\r\nNew API key: abc123\r\n\r\nNOTE: granted\r\nfw-lab $ "])
    handle = device_access(shell)
    handle.credential = credential()
    answer = handle.generate_api_key('execute api-user generate-key "netops-sg-x-u"', exec_fortios.prompt_spec("fw-lab"))
    assert fortios.api_key(answer) == "abc123"
    assert shell.sent == ['execute api-user generate-key "netops-sg-x-u"', "pw-value"]


def test_device_access_never_sends_the_password_without_the_prompt():
    shell = Shell([b"fw-lab $ ", b"Command fail. Return code -3\r\nfw-lab $ "])
    handle = device_access(shell)
    handle.credential = credential()
    with pytest.raises(access.AccessError):
        handle.generate_api_key('execute api-user generate-key "netops-sg-x-u"', exec_fortios.prompt_spec("fw-lab"))
    assert shell.sent == ['execute api-user generate-key "netops-sg-x-u"']
    handle = device_access(Shell([b"fw-lab $ "]))
    handle.credential = credential("ssh-key")
    with pytest.raises(access.AccessError):
        handle.generate_api_key("execute api-user generate-key x", exec_fortios.prompt_spec("fw-lab"))


@pytest.mark.parametrize("asked,sent", [
    (b'next\r\r\nPlease enter current administrator password: ', ["config system api-user", "next", "pw-value", "end"]),
    (b"next\r\n\r\nfw-lab (api-user) $ ", ["config system api-user", "next", "end"]),
])
def test_device_access_answers_the_password_prompt_of_a_line_only_when_asked(asked, sent):
    answers = [b"fw-lab $ ", b"config system api-user\r\n\r\nfw-lab (api-user) $ ", asked]
    if "pw-value" in sent:
        answers.append(b"\r\n\r\nfw-lab (api-user) $ ")
    shell = Shell(answers + [b"end\r\n\r\nfw-lab $ "])
    handle = device_access(shell)
    handle.credential = credential()
    steps = ["config system api-user", ("password", "next"), "end"]
    assert handle.apply(steps, exec_fortios.prompt_spec("fw-lab")) == 3
    assert shell.sent == sent


def test_schema_prechecks_stay_cli_script():
    from netops_admin import exec_schema_fortios
    device = FakeFortiOSWebhook()
    snapshot = device.snapshot()
    plan = {"firmware": "8.0.2 build0251", "table": "firewall policy", "op": "create", "key": "9001", "inverse": []}
    assert exec_schema_fortios.prechecks(device, SimpleNamespace(address="fw.example"), snapshot, None) == []
    assert exec_schema_fortios.plan_prechecks(device, SimpleNamespace(address="fw.example"), plan, snapshot) == []
    assert exec_fortios.prechecks(device, SimpleNamespace(address="fw.example"), snapshot, None) == []
    assert exec_fortios.plan_prechecks(device, SimpleNamespace(address="fw.example"), plan, snapshot) == [
        "the webhook safeguard needs the device address as an IPv4 address, not a host name"]


@pytest.mark.parametrize("fake", [Fake768, FakeFortiOSWebhook])
def test_a_trigger_that_is_not_scheduled_is_not_a_verified_safeguard(tmp_path, fake):
    device = fake()
    device.trigger_type_override = "event-based"
    record = execute.apply(runtime(tmp_path, device), "lab", policy())
    assert record["result"] == "reverted" and "safeguard_not_verified" in steps(record)
    assert "9001" not in device.policies and own_objects(device) == []
    assert not any(block[0] == "config firewall policy" for block in device.applied_blocks)


def webhook_check(tmp_path, device, **fields):
    report = readiness.doctor(runtime(tmp_path, device, **fields), "lab")
    [item] = [item for item in report["checks"] if item["check"] == "webhook safeguard"]
    return item


def test_doctor_reports_a_ready_webhook_safeguard(tmp_path):
    device = FakeFortiOSWebhook()
    device.admin_sport = 8443
    item = webhook_check(tmp_path, device)
    assert item["status"] == readiness.OK
    assert "192.0.2.1" in item["detail"] and "8443" in item["detail"] and "port1" in item["detail"]
    assert device.applied_blocks == [] and device.issued == []


def test_doctor_says_the_webhook_is_not_used_on_cli_script_firmware(tmp_path):
    item = webhook_check(tmp_path, Fake768(), address="fw-lab.example")
    assert item["status"] == readiness.OK and "cli-script" in item["detail"]


@pytest.mark.parametrize("change,expected", [
    (lambda d, f: f.update(address="fw-lab.example"), "device address as an IPv4 address"),
    (lambda d, f: setattr(d, "interface_lines", {}), "no interface holds that address"),
    (lambda d, f: d.interface_lines.update(port1=["set ip 192.0.2.1 255.255.255.0", "set allowaccess ping ssh"]),
     "needs https in allowaccess of interface port1"),
    (lambda d, f: setattr(d, "credential", SimpleNamespace(login="netops-rw", kind="ssh-key")),
     "needs a password write credential"),
    (lambda d, f: d.api_users.update({"netops-sg-0123456789ab-u": {"trusthost": []}}),
     "a safeguard of an earlier operation is still installed: netops-sg-0123456789ab-u"),
    (lambda d, f: d.write_admins.update({"netops-rw": "netops-rw-prof"}),
     "needs the write account netops-rw with access profile super_admin on FortiOS 8.0.1 and later"),
    (lambda d, f: d.write_admins.clear(), "cannot find the write account netops-rw in system admin; on FortiOS"
     " 8.0.1 and later it needs access profile super_admin"),
    (lambda d, f: setattr(d, "admin_sport", 70000), "the HTTPS administration port cannot be read"),
])
def test_doctor_names_what_the_webhook_safeguard_lacks(tmp_path, change, expected):
    device = FakeFortiOSWebhook()
    fields = {}
    change(device, fields)
    item = webhook_check(tmp_path, device, **fields)
    assert item["status"] == readiness.REFUSED and expected in item["detail"]
    assert device.applied_blocks == [] and device.issued == []


def test_the_audit_after_a_change_ignores_only_the_own_safeguard(tmp_path):
    device = FakeFortiOSWebhook()
    before = audit_gate.baseline("fortios", device.snapshot(), "lab")
    own, foreign = "netops-sg-aaaaaaaaaaaa-", "netops-sg-bbbbbbbbbbbb-"
    device.api_users.update({own + "u": {"trusthost": []}, foreign + "u": {"trusthost": []}})
    after = device.snapshot()
    assert audit_gate.new_blocking("fortios", before, after, "lab", own=own) == ["fortios.mgmt.netops-safeguard-leftover"]
    device.api_users.pop(foreign + "u")
    assert audit_gate.new_blocking("fortios", before, device.snapshot(), "lab", own=own) == []
    assert audit_gate.new_blocking("fortios", before, device.snapshot(), "lab") == ["fortios.mgmt.netops-safeguard-leftover"]
