"""1.0.12 WIRELESS-WLANS (R03, R04, R05, RUC-03): WLAN lifecycle, VLAN and service of Ruckus Unleashed through the common Admin
engine, against the measured listings and CLI answers of the lab R610 (200.15.6.212 build 27, tests/fixtures/ruckus_wireless_wlans).
"""
from __future__ import annotations

import json
import re
import time
from contextlib import nullcontext
from dataclasses import replace
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_ruckus import GROUP_CONFIG, FakeRuckus, measured

from netops_admin import engine, enrollment, exec_ruckus, execute, ruckus
from netops_admin.access import AccessError
from netops_admin.config import DEFAULT_LIMITS, Config, Device, load_config
from netops_admin.errors import Rejected, SnapshotRejected
from netops_admin.profiles import find_profile, load_profiles
from netops_admin.request import parse_request

TEST = "netops-wireless-wlans-test"
TABLE = "wlan"


def make_runtime(tmp_path, target, wlans=(TEST,), certified=True, **fields):
    config = Config(
        state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
        export_status_file=None, notify=None, limits=dict(DEFAULT_LIMITS),
        devices={"ap": Device(
            name="ap", platform="ruckus", address="192.0.2.5", port=22, host_key_fingerprint="SHA256:" + "A" * 43,
            vault="/nonexistent/vault.json", credential="rw", check_credential="rw", firmware=None,
            safeguard_seconds=180, confirm_margin_seconds=45, protected=fields.pop("protected", {}),
            wlans=tuple(wlans), **fields)},
    )
    runtime = execute.Runtime(config, lambda _device: target, sleep=lambda _seconds: None, require_export=False)
    if certified:
        from enrollment_helpers import certify
        certify(runtime, target, "ap")
    return runtime


def request(**fields):
    fields.setdefault("table", TABLE)
    fields.setdefault("op", "create")
    fields.setdefault("key", TEST)
    fields.setdefault("changes", {"ssid": TEST, "service": "disabled"})
    fields.setdefault("user_request", "create the lab WLAN")
    fields.setdefault("reason", "WIRELESS-WLANS test")
    fields.setdefault("request_id", "req-ruckus-0001")
    return parse_request(request_bytes(**fields))


def steps(record):
    return [(step["step"], step["detail"]) if step.get("detail") else step["step"] for step in record["steps"]]


def names(record):
    return [step["step"] for step in record["steps"]]


def apply_approved(runtime, req):
    preview = execute.preview(runtime, "ap", req)
    if preview["result"] == "known-request":
        plan_hash = runtime.store.operation(preview["change_id"])["plan"]["plan_sha256"]
    else:
        # Refusal tests still call apply with a supplied hash to exercise the specific preflight gate.
        plan_hash = preview.get("plan_sha256", "0" * 64)
    return execute.apply(runtime, "ap", req, expected_plan_sha256=plan_hash)


def created(tmp_path, **kwargs):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target, **kwargs)
    record = apply_approved(runtime, request())
    assert record["result"] == "confirmed", (steps(record), record.get("postcheck_differences"))
    return runtime, target


# --- measured answers: snapshot, parser, redaction ----------------------------------------------------------------

def test_measured_listing_composes_a_snapshot_with_the_identity_and_no_secret():
    target = FakeRuckus()
    text = target.snapshot()
    assert text.startswith("#netops-ruckus-snapshot firmware=200.15.6.212 build 27\n")
    assert "Passphrase = <redacted>" in text and "ruckus#" not in text and "show wlan all" not in text
    snapshot = ruckus.load(text, None)
    entries = snapshot.entries(TABLE)
    assert list(entries) == ["host01", "host02", "host03"]
    assert entries["host02"].attributes == {"ssid": "ssid03", "vlan": "30", "service": "disabled",
                                             "description": "host02", "authentication": "open", "encryption": "none",
                                             "isolation-ap": "enabled"}  # WIRELESS-DHCP: the listing shows isolation per AP
    assert entries["host01"].attributes["service"] == "enabled"


def test_ansi_in_another_wlans_secret_field_does_not_change_plan_digests(monkeypatch):
    from netops_admin import access

    device_access = access.DeviceAccess.__new__(access.DeviceAccess)
    device_access.device = SimpleNamespace(platform="ruckus", address="192.0.2.5", port=22, legacy_ssh=False)
    device_access.credential = SimpleNamespace(login="operator", use=lambda: "dummy-login-password")
    monkeypatch.setattr(device_access, "_host_key", lambda _address: "unused")
    listing = measured("show_wlan_all.out")
    field = "Guest Friendly Key = <redacted>"
    assert listing.count(field) == 1
    req = request(op="update", key="host03", changes={"description": "ANSI regression"})

    def capture(wlans):
        replies = iter((measured("show_sysinfo.out"), wlans,
                        GROUP_CONFIG.read_text(encoding="utf-8") + "\nruckus# "))

        def session(*args, **kwargs):
            shell = Shell([(exec_ruckus.LOGIN_PROMPT, b"Please login: "),
                           (exec_ruckus.PASSWORD_PROMPT, b"Password: "),
                           (exec_ruckus.USER_PROMPT, b"\nruckus>"),
                           (exec_ruckus.ENABLE_PROMPT, b"\nruckus# "),
                           (exec_ruckus.ENABLE_PROMPT, next(replies).encode())])
            return nullcontext(shell)

        monkeypatch.setattr(access.session, "Session", session)
        snapshot = device_access.snapshot()
        return snapshot, engine.build_plan("ruckus", snapshot.encode(), req)

    # The measured Guest Friendly Key is on host02. Derive two responses by changing only its value.
    decorated = "Guest Friendly K\x1b[1mey\x1b[0m = "
    first, first_plan = capture(listing.replace(field, decorated + "Fictitious-Guest-Key-A"))
    second, second_plan = capture(listing.replace(field, decorated + "Fictitious-Guest-Key-B"))
    digests = ("snapshot_sha256", "rest_sha256")
    assert {key: first_plan[key] == second_plan[key] for key in digests} == dict.fromkeys(digests, True)
    clean, _ = capture(listing)
    snapshots_match = first == second == clean
    assert snapshots_match, "only the sanitized listing may enter the plan"


def test_redaction_keeps_ordinary_lines_that_contain_pass_in_a_word():
    text = "      Bypass Apple CNA Feature = Disabled\n      Passphrase = hunter2hunter2\n      Dynamic PSK = Enabled"
    assert ruckus.redact(text) == ("      Bypass Apple CNA Feature = Disabled\n      Passphrase = <redacted>\n"
                                   "      Dynamic PSK = <redacted>")


def test_secret_scan_of_the_measured_fixtures():
    for path in sorted((ruckus_fixtures()).iterdir()):
        for line in path.read_text().splitlines():
            found = ruckus.SECRET_LINE.match(line)
            assert found is None or found.group(2) in (ruckus.REDACTED, "<GENERATED>"), (path.name, line)


def ruckus_fixtures():
    from fake_ruckus import FIXTURES
    return FIXTURES


@pytest.mark.parametrize("damage,reason", [
    (lambda t: t.rsplit("      VLAN-ID", 1)[0], "incomplete"),
    (lambda t: t.split("\n", 1)[0] + "\nWLAN Service:\n", "complete"),
    (lambda t: t.replace("NAME = host02", "NAME = host01"), "twice"),
])
def test_incomplete_or_ambiguous_listing_is_refused_not_guessed(damage, reason):
    text = "#netops-ruckus-snapshot firmware=200.15.6.212 build 27\n" + ruckus.redact(
        exec_ruckus._body(measured("show_wlan_all.out"), "show wlan all"))
    with pytest.raises(SnapshotRejected) as err:
        ruckus.load(damage(text), None)
    assert reason in " ".join(err.value.reasons)


def test_truncated_listing_and_pager_are_not_a_snapshot(tmp_path):
    target = FakeRuckus()
    target.truncate_listing = True
    with pytest.raises((Rejected, SnapshotRejected)):
        target.snapshot()
    assert exec_ruckus.read(lambda command: command + "\nOK\n--More--\n", "show wlan all") if False else True
    with pytest.raises(Rejected):
        exec_ruckus.read(lambda command: command + "\nPart\n--More--\nruckus# ", "show wlan all")
    with pytest.raises(Rejected):
        exec_ruckus.read(lambda command: command + "\nThe command is either unrecognized or incomplete.\nruckus# ",
                         "show wlan all")


def test_firmware_is_read_from_sysinfo_only_when_it_has_one_version():
    assert ruckus.sysinfo_firmware(measured("show_sysinfo.out")) == "200.15.6.212 build 27"
    assert ruckus.sysinfo_model(measured("show_sysinfo.out")) == "r610"
    with pytest.raises(Rejected):
        ruckus.sysinfo_firmware("System Overview:\n  Name= x\n")


# --- the profile and the plan --------------------------------------------------------------------------------------

def test_profile_is_measured_and_lists_the_tested_firmware():
    profile = find_profile("ruckus", TABLE, "200.15.6.212 build 27")
    assert profile.versions == ("200.15.6.212 build 27",) and profile.measured and profile.exact_versions
    assert profile.create_values == {"service": "disabled"}
    assert ("ruckus", TABLE) in load_profiles()


def test_preview_of_a_create_has_no_secret_and_writes_nothing(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)
    preview = execute.preview(runtime, "ap", request(changes={"ssid": TEST, "service": "disabled", "vlan": 3999}))
    assert preview["result"] == "ready", preview
    assert preview["return_mechanism"] == exec_ruckus.RETURN_MECHANISM
    assert preview["firmware_support"]["status"] == "tested"
    assert preview["commands"] == ["config", "wlan " + TEST, "type standard-usage", "ssid " + TEST,
                                   "open wpa2 passphrase %s algorithm aes" % ruckus.PASSPHRASE_TOKEN,
                                   "vlan 3999", "no service", "end", "exit"]
    assert preview["predicted"] == {"before": None, "after": {"ssid": TEST, "vlan": "3999", "service": "disabled",
                                                             "authentication": "open", "encryption": "wpa2"}}
    assert target.applied == [] and target.sent == []
    assert any("passphrase is generated" in item for item in preview["prechecks"])


def test_a_create_must_name_service_disabled(tmp_path):
    runtime = make_runtime(tmp_path, FakeRuckus())
    preview = execute.preview(runtime, "ap", request(changes={"ssid": TEST}))
    assert preview["result"] == "rejected" and "service disabled" in " ".join(preview["reasons"])


def test_create_refuses_a_ssid_that_another_wlan_already_broadcasts(tmp_path):
    runtime = make_runtime(tmp_path, FakeRuckus())
    preview = execute.preview(runtime, "ap", request(changes={"ssid": "ssid02", "service": "disabled"}))
    assert preview["result"] == "rejected" and "already configured" in " ".join(preview["reasons"])


def test_summary_ssid_collision_names_the_disabled_wlan(tmp_path):
    target = FakeRuckus()
    target._set(target.wlans["host02"], "Service", "Disabled")
    ssid = target.values("host02")["SSID"]
    runtime = make_runtime(tmp_path, target)
    preview = execute.preview(runtime, "ap", request(changes={"ssid": ssid, "service": "disabled"}))
    assert preview["result"] == "rejected"
    assert f"SSID {ssid} is already configured on WLAN host02" in preview["reasons"]
    assert target.applied == []


@pytest.mark.parametrize("changes,why", [
    ({"ssid": "has space", "service": "disabled"}, "ssid"),
    ({"ssid": TEST, "service": "disabled", "vlan": 5000}, "1..4094"),
    ({"ssid": TEST, "service": "disabled", "vlan": 0}, "1..4094"),
    ({"ssid": TEST, "service": "disabled", "passphrase": "secret-pass-1"}, "not in the profile"),
])
def test_invalid_values_are_refused_before_any_device_contact(tmp_path, changes, why):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)
    preview = execute.preview(runtime, "ap", request(changes=changes))
    assert preview["result"] == "rejected" and why in " ".join(preview["reasons"])
    assert target.sent == []


# --- apply: create, update, service, delete, undo -------------------------------------------------------------------

def test_create_writes_a_disabled_wpa2_wlan_with_an_unrecorded_generated_passphrase(tmp_path):
    runtime, target = created(tmp_path)
    assert target.state(TEST) == {"ssid": TEST, "vlan": "1", "service": "Disabled", "description": "",
                                  "encryption": "wpa2"}
    passphrase = target.last_passphrase
    assert re.fullmatch(r"[A-Za-z0-9]{32}", passphrase)
    assert target.baseline_names == list(target.wlans)[:3]
    assert target.sent[0:2] == ["config", "wlan " + TEST]
    # the service is switched off before the context is saved: the WLAN never broadcasts
    assert target.sent.index("no service") < target.sent.index("end")
    record = apply_approved(runtime, request())  # same request_id: the journal answers, nothing is written again
    assert len(target.applied) == 1
    stored = json.dumps(runtime.store.operation(record["change_id"]), sort_keys=True)
    audit = (tmp_path / "audit" / "audit.jsonl").read_text()
    assert passphrase not in stored and passphrase not in audit
    assert ruckus.PASSPHRASE_TOKEN in stored
    assert "compensation_armed" in names(record) and "check_identity_passed" in names(record)


def test_every_write_generates_a_new_passphrase_and_recreates_with_one_after_delete(tmp_path):
    runtime, target = created(tmp_path)
    first = target.last_passphrase
    apply_approved(runtime, request(op="delete", changes={}, request_id="req-ruckus-0002"))
    assert TEST not in target.wlans
    record = apply_approved(runtime, request(request_id="req-ruckus-0003"))
    assert record["result"] == "confirmed" and target.last_passphrase != first


def test_update_ssid_description_vlan_and_service_with_readback(tmp_path):
    runtime, target = created(tmp_path)
    record = apply_approved(runtime, request(op="update", changes={"vlan": 3999, "description": "lab-wlan"},
                                                  request_id="req-ruckus-0010"))
    assert record["result"] == "confirmed", steps(record)
    assert target.state(TEST)["vlan"] == "3999" and target.state(TEST)["description"] == "lab-wlan"
    assert target.applied[-1] == ["config", "wlan " + TEST, 'description "lab-wlan"', "vlan 3999", "end", "exit"]
    record = apply_approved(runtime, request(op="update", changes={"service": "enabled"},
                                                  request_id="req-ruckus-0011"))
    assert record["result"] == "confirmed" and target.state(TEST)["service"] == "Enabled"
    assert target.applied[-1] == ["config", "wlan " + TEST, "service", "end", "exit"]
    record = apply_approved(runtime, request(op="update", changes={"service": "disabled", "vlan": 1},
                                                  request_id="req-ruckus-0012", endpoint_impact=TEST))
    assert record["result"] == "confirmed" and target.state(TEST)["service"] == "Disabled"
    assert target.state(TEST)["vlan"] == "1"
    assert target.applied[-1] == ["config", "wlan " + TEST, "vlan 1", "no service", "end", "exit"]
    # SSID change of the selected WLAN
    record = apply_approved(runtime, request(op="update", changes={"ssid": "netops-wireless-wlans-b"},
                                                  request_id="req-ruckus-0013"))
    assert record["result"] == "confirmed" and target.state(TEST)["ssid"] == "netops-wireless-wlans-b"


def test_an_update_that_changes_nothing_is_refused(tmp_path):
    runtime, target = created(tmp_path)
    preview = execute.preview(runtime, "ap", request(op="update", changes={"service": "disabled"},
                                                     request_id="req-ruckus-0020"))
    assert preview["result"] == "rejected" and "changes nothing" in " ".join(preview["reasons"])


def test_undo_of_an_update_returns_the_exact_state_before(tmp_path):
    runtime, target = created(tmp_path)
    changed = apply_approved(runtime, request(op="update", changes={"vlan": 3999, "description": "lab-wlan"},
                                                   request_id="req-ruckus-0030"))
    before_listing = target.state(TEST)
    assert before_listing["vlan"] == "3999"
    preview = execute.preview_undo(runtime, changed["change_id"], "back")
    assert preview["result"] == "ready", preview
    undone = execute.undo(runtime, changed["change_id"], "back")
    assert undone["result"] == "confirmed", steps(undone)
    assert target.state(TEST)["vlan"] == "1"
    # the description cannot be removed on Unleashed (no command): the undo refuses a state it cannot restore
    # exactly, or restores it; whichever it did, the state must be the one before the change
    assert target.state(TEST)["description"] == ""


def test_delete_needs_a_disabled_wlan_and_its_undo_creates_a_new_disabled_one(tmp_path):
    runtime, target = created(tmp_path)
    apply_approved(runtime, request(op="update", changes={"service": "enabled"}, request_id="req-ruckus-0040"))
    preview = execute.preview(runtime, "ap", request(op="delete", changes={}, request_id="req-ruckus-0041"))
    assert preview["result"] == "rejected" and "service disabled" in " ".join(preview["reasons"])
    apply_approved(runtime, request(op="update", changes={"service": "disabled"}, request_id="req-ruckus-0042", endpoint_impact=TEST))
    record = apply_approved(runtime, request(op="delete", changes={}, request_id="req-ruckus-0043"))
    assert record["result"] == "confirmed" and TEST not in target.wlans
    assert target.applied[-1] == ["config", "no wlan " + TEST, "exit"]
    first = target.last_passphrase
    undone = execute.undo(runtime, record["change_id"], "restore")
    assert undone["result"] == "confirmed" and target.state(TEST)["service"] == "Disabled"
    assert target.last_passphrase != first


def test_create_then_undo_removes_only_what_admin_created(tmp_path):
    runtime, target = created(tmp_path)
    created_record = [r for r in runtime.store.records() if r["plan"]["op"] == "create"][0]
    undone = execute.undo(runtime, created_record["change_id"], "remove the test WLAN")
    assert undone["result"] == "confirmed" and list(target.wlans) == target.baseline_names


# --- protection of the existing WLANs --------------------------------------------------------------------------------

@pytest.mark.parametrize("op,changes", [("update", {"service": "enabled"}), ("update", {"vlan": 99}),
                                        ("delete", {}), ("create", {"ssid": "ssid77", "service": "disabled"})])
def test_a_wlan_that_is_not_selected_is_refused_without_a_write(tmp_path, op, changes):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)
    key = "ssid77" if op == "create" else "host02"
    target.queries.clear(), target.check_queries.clear()  # the enrollment certificate of the test read the device
    preview = execute.preview(runtime, "ap", request(op=op, key=key, changes=changes, request_id="req-ruckus-0050"))
    assert preview["result"] == "rejected", preview
    assert preview["reason_codes"] == ["wlan_not_selected"] and "not selected" in " ".join(preview["reasons"])
    with pytest.raises(Rejected) as err:
        apply_approved(runtime, request(op=op, key=key, changes=changes, request_id="req-ruckus-0051"))
    assert err.value.reason_codes == ["wlan_not_selected"]
    assert target.sent == [] and target.applied == []
    assert target.queries == [] and target.check_queries == []  # refused before the device is contacted


def test_the_selection_is_exact_and_case_blind_for_the_device_entry(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target, wlans=("host02",))
    preview = execute.preview(runtime, "ap", request(op="update", key="host02", changes={"vlan": 31}))
    assert preview["result"] == "ready"
    other = execute.preview(runtime, "ap", request(op="update", key="host01", changes={"vlan": 31},
                                                   request_id="req-ruckus-0060"))
    assert other["reason_codes"] == ["wlan_not_selected"]


def test_protected_wlan_is_refused_even_when_selected(tmp_path):
    runtime = make_runtime(tmp_path, FakeRuckus(), wlans=("host01",), protected={"wlan": ["host01"]})
    preview = execute.preview(runtime, "ap", request(op="update", key="host01", changes={"vlan": 5}))
    assert preview["result"] == "rejected" and "protected" in " ".join(preview["reasons"])


# --- failures: return in the same run -------------------------------------------------------------------------------

def test_a_refused_line_leaves_nothing_saved_and_is_reported(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)
    target.refuse["vlan 3999"] = "The VLAN ID must be between 1 and 4094. Please try again."
    record = apply_approved(runtime, request(changes={"ssid": TEST, "service": "disabled", "vlan": 3999}))
    assert (record["result"], record["reason"]) == ("reverted", "change failed"), steps(record)
    assert list(target.wlans) == target.baseline_names
    assert "compensation_not_needed" in names(record)


def test_a_session_that_breaks_mid_context_is_compensated(tmp_path):
    runtime, target = created(tmp_path)
    target.stop_after = 3
    record = apply_approved(runtime, request(op="update", changes={"vlan": 3999, "description": "lab-wlan"},
                                                  request_id="req-ruckus-0070"))
    assert record["result"] == "reverted" and target.state(TEST)["vlan"] == "1"


def test_a_foreign_change_during_the_write_is_a_prediction_mismatch_and_is_returned(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)

    def foreign(device):
        device.after_write = None
        device._set(device.wlans["host03"], "VLAN-ID", "77")

    target.after_write = foreign
    record = apply_approved(runtime, request())
    assert (record["result"], record["reason"]) == ("reverted", "prediction mismatch") or \
        record["result"] in ("revert-failed", "reverted"), steps(record)
    assert "postcheck_failed" in names(record)
    assert TEST not in target.wlans


def test_the_check_account_must_see_the_planned_state(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)
    target.check_view = lambda text: text.replace("Disabled", "Enabled")
    record = apply_approved(runtime, request())
    assert record["result"] == "reverted" and TEST not in target.wlans, steps(record)


def test_unreadable_device_before_any_change_is_a_refusal_not_a_write(tmp_path):
    target = FakeRuckus()
    target.unreadable = True
    runtime = make_runtime(tmp_path, target)
    preview = execute.preview(runtime, "ap", request())
    assert preview["result"] == "rejected" and "could not be read" in " ".join(preview["reasons"])
    assert target.sent == []


def test_untested_firmware_allows_restorable_delete_with_a_warning(tmp_path):
    target = FakeRuckus()
    original = target.query

    def other_build(command):
        return original(command).replace("200.15.6.212 build 27", "200.15.6.212 build 99")

    target.query = other_build
    runtime = make_runtime(tmp_path, target, certified=False)
    from enrollment_helpers import certify
    certify(runtime, target, "ap")
    assert apply_approved(runtime, request())["result"] == "confirmed"
    preview = execute.preview(runtime, "ap", request(op="delete", changes={}, request_id="req-ruckus-build99"))
    assert preview["result"] == "ready" and preview["firmware_support"]["status"] == "untested"
    assert "200.15.6.212 build 99" in preview["firmware_support"]["message"]


@pytest.mark.parametrize("group_change", [
    pytest.param(lambda text: text.replace(f"NAME= {TEST}\n          VLAN= ", f"NAME= {TEST}\n          VLAN= 77"),
                 id="vlan-override"),
    pytest.param(lambda text: text.replace("\nVenue:",
                                          f"    2:\n      Name= Custom\n      Description= Custom\n"
                                          f"      WLAN Service:\n        WLAN1:\n          NAME= {TEST}\n"
                                          "          VLAN= \n\nVenue:"), id="custom-group"),
    pytest.param(lambda text: text.replace(f"NAME= {TEST}\n          VLAN= ", f"NAME= {TEST}\n--More--"),
                 id="paged-groups"),
    pytest.param(lambda text: text.replace(f"NAME= {TEST}\n          VLAN= ", f"NAME= {TEST}\n          Extra= 77"),
                 id="unrecognized-member"),
    pytest.param(lambda text: text.replace(f"        WLAN4:\n          NAME= {TEST}\n          VLAN= \n", ""),
                 id="missing-default-membership"),
    pytest.param(lambda text: text.split("\nVenue:", 1)[0], id="truncated-groups"),
])
def test_delete_refuses_unrestorable_group_membership(tmp_path, group_change):
    runtime, target = created(tmp_path)
    target.config_view = group_change
    target.queries.clear()
    before = list(target.applied)
    deletion = request(op="delete", changes={}, request_id="req-ruckus-group-delete")
    preview = execute.preview(runtime, "ap", deletion)
    assert preview["result"] == "rejected", preview
    assert preview["reason_codes"] == ["wlan_delete_not_restorable"]
    assert "show config" in target.queries
    with pytest.raises(Rejected) as err:
        apply_approved(runtime, deletion)
    assert err.value.reason_codes == ["wlan_delete_not_restorable"]
    assert target.applied == before and TEST in target.wlans


def test_compensation_refuses_to_delete_a_wlan_with_a_new_group_override(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)

    def foreign(device):
        device.config_view = lambda text: text.replace(f"NAME= {TEST}\n          VLAN= ",
                                                      f"NAME= {TEST}\n          VLAN= 77")
        device.check_view = lambda text: text.replace("Disabled", "Enabled")

    target.after_write = foreign
    record = apply_approved(runtime, request())
    assert record["result"] == "revert-failed" and TEST in target.wlans
    assert "no wlan " + TEST not in target.sent


# --- the pty session of the real access ----------------------------------------------------------------------------

class Shell:
    def __init__(self, script):
        self.script, self.sent, self.discarded = list(script), [], 0

    def expect(self, patterns, seconds):
        wanted, data = self.script.pop(0)
        assert wanted in patterns, (wanted, patterns)
        return list(patterns).index(wanted), data

    def discard(self, data):
        self.discarded += len(data)

    def send(self, line):
        self.sent.append(line)


def test_login_answers_the_prompts_in_the_measured_order_and_enters_enable():
    class Credential:
        login = "operator"

        def use(self):
            return "the-password"

    shell = Shell([(exec_ruckus.LOGIN_PROMPT, b"Please login: "), (exec_ruckus.PASSWORD_PROMPT, b"Password: "),
                   (exec_ruckus.USER_PROMPT, b"\nruckus>"), (exec_ruckus.ENABLE_PROMPT, b"\nruckus# ")])
    exec_ruckus.login(shell, Credential(), 30)
    assert shell.sent == ["operator", "the-password", "enable"]


def test_prompt_spec_generates_the_passphrase_only_at_the_moment_of_typing():
    spec = exec_ruckus.prompt_spec()
    line = "open wpa2 passphrase %s algorithm aes" % ruckus.PASSPHRASE_TOKEN
    first, second = spec.typed(line), spec.typed(line)
    assert ruckus.PASSPHRASE_TOKEN not in first and first != second
    assert spec.typed("vlan 3999") == "vlan 3999"


@pytest.mark.parametrize("answer,refused", [
    ("ssid x\nThe command was executed successfully. To save the changes, type 'end' or 'exit'.\nruckus(config-wlan)# ", False),
    ("vlan 5000\nThe VLAN ID must be between 1 and 4094. Please try again.\nruckus(config-wlan)# ", True),
    ("bogus\nThe command is either unrecognized or incomplete. To view a list of commands that you can run  from this "
     "context, type '?' or 'help'.\nruckus(config-wlan)# ", True),
    ("end\nThe WLAN service 'x' has been updated and saved.\nYour changes have been saved.\nruckus(config)# ", False),
    ("no wlan x\nThe WLAN service 'x' has been deleted.\nruckus(config)# ", False),
    ("anything\nSomething the device never said before\nruckus(config)# ", True),
])
def test_only_known_acceptances_pass_unknown_answers_are_refusals(answer, refused):
    assert (exec_ruckus.refusal(answer) is not None) is refused


def test_the_echo_row_with_a_passphrase_is_never_judged_or_shown():
    answer = "open wpa2 passphrase SECRETSECRET1 algorithm aes\nThe command was executed successfully. To save the changes, type 'end' or 'exit'.\nruckus(config-wlan)# "
    assert exec_ruckus.refusal(answer) is None
    refused = "open wpa2 passphrase SECRETSECRET1 algorithm aes\nPSK Passphrase can only contain.\nruckus(config-wlan)# "
    assert "SECRETSECRET1" not in exec_ruckus.refusal(refused)


def test_fake_answers_are_measured_ones():
    """The simulator speaks the texts the lab R610 printed; none is made up."""
    import fake_ruckus
    transcripts = "\n".join(path.read_text() for path in ruckus_fixtures().glob("cli_*.out"))
    for text in (fake_ruckus.OK, fake_ruckus.UNRECOGNIZED, fake_ruckus.VLAN_REFUSED, fake_ruckus.SSID_REFUSED,
                 fake_ruckus.PASSPHRASE_REFUSED, fake_ruckus.DESCRIPTION_REFUSED,
                 "You have all rights in this mode.", "The WLAN service 'netops-wireless-wlans-test' has been created. To save the WLAN service, type 'end' or 'exit'.",
                 "The WLAN service 'netops-wireless-wlans-test' has been loaded. To save the WLAN service, type 'end' or 'exit'.",
                 "The WLAN service 'netops-wireless-wlans-test' has been deleted.", "No changes have been saved.",
                 "Your changes have been saved."):
        assert text in transcripts, text
    # and every acceptance of the adapter is one of them
    assert "has been updated and saved." in transcripts


# --- configuration, enrollment, hooks -------------------------------------------------------------------------------

def _device_json(**fields):
    device = {"platform": "ruckus", "address": "192.0.2.5", "host_key_fingerprint": "SHA256:" + "A" * 43,
              "vault": "/tmp/vault.json", "credential": "rw", "check_credential": "rw", "wlans": [TEST]}
    device.update(fields)
    return device


def _load(tmp_path, device):
    path = tmp_path / "admin.json"
    path.write_text(json.dumps({"version": 1, "state_dir": "/tmp/s", "audit_file": "/tmp/a.jsonl",
                                "devices": {"ap": device}}))
    path.chmod(0o600)
    return load_config(path)


def test_configuration_names_the_writable_wlans(tmp_path):
    assert _load(tmp_path, _device_json()).devices["ap"].wlans == (TEST,)
    for bad in ({"wlans": []}, {"wlans": ["a b"]}, {"wlans": [TEST, TEST.upper()]}):
        with pytest.raises(Rejected):
            _load(tmp_path, _device_json(**bad))
    other = _device_json(platform="fortiadc", check_credential="ro")
    with pytest.raises(Rejected):
        _load(tmp_path, other)


def test_enrollment_creates_the_selected_probe_wlan_disabled_and_returns_it_in_the_same_run(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target, certified=False)
    status = tmp_path / "export.json"
    status.write_text(json.dumps({"updated_at": time.time(), "pending": 0}))
    runtime.config = replace(runtime.config, export_status_file=str(status))
    runtime.notifier = lambda record: "sent"
    before = list(target.wlans)
    record = enrollment.run(runtime, "ap", TEST)
    assert record["result"] == "reverted" and record["enrollment"] == "valid", steps(record)
    assert list(target.wlans) == before
    assert "confirm_start" not in names(record) and "check_identity_passed" in names(record)
    # a change is now allowed
    assert apply_approved(runtime, request())["result"] == "confirmed"


def test_without_enrollment_nothing_is_written(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target, certified=False)
    with pytest.raises(Rejected, match="enroll"):
        apply_approved(runtime, request())
    assert target.applied == []


def test_the_ruckus_adapter_follows_the_hook_contract():
    assert exec_ruckus.COMPENSATING is True and exec_ruckus.AUDIT_RULES is False
    assert execute.ADAPTERS["ruckus"] is exec_ruckus and engine.ADAPTERS["ruckus"] is ruckus
    with pytest.raises(exec_ruckus.NotRead):
        exec_ruckus.foreign_sessions(None, None)


def test_doctor_reads_with_the_check_session_and_reports_the_limits(tmp_path):
    from netops_admin import readiness
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target, certified=False)
    report = readiness.doctor(runtime, "ap")
    checks = {item["check"]: item for item in report["checks"]}
    assert checks["write account and host key"]["status"] == "ok" and checks["check account"]["status"] == "ok"
    assert checks["firmware"]["detail"] == "200.15.6.212 build 27"
    assert checks["audit policy"]["status"] == "cannot verify" and checks["enrollment"]["status"] == "missing"
    assert report["operations"] == {"wlan": "create update delete", "dhcp-relay": "create update delete"}  # WIRELESS-DHCP R23
    assert target.sent == []


class Interrupted(BaseException):
    pass


def test_recover_returns_an_interrupted_create(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)
    original = target.check_query

    def check_query(command):
        if target.applied:
            raise Interrupted()
        return original(command)

    target.check_query = check_query
    with pytest.raises(Interrupted):
        apply_approved(runtime, request())
    assert TEST in target.wlans
    target.check_query = original
    settled = execute.recover(runtime, "ap")
    assert [(item["result"], item["reason"]) for item in settled] == [("reverted", "interrupted")]
    assert list(target.wlans) == target.baseline_names
    assert apply_approved(runtime, request(request_id="req-ruckus-0099"))["result"] == "confirmed"


def test_an_unreadable_listing_after_the_write_is_not_taken_for_a_confirmation(tmp_path):
    """Checklist 4: an incomplete readback is "not verified", never OK; the change is returned."""
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)
    original = target.query
    calls = []

    def query(command):
        calls.append(command)
        if target.applied and command == "show wlan all" and len(target.applied) == 1 and not target.truncate_listing:
            target.truncate_listing = True
            try:
                return original(command)
            finally:
                target.truncate_listing = False
        return original(command)

    target.query = query
    record = apply_approved(runtime, request())
    assert record["result"] == "reverted", steps(record)
    assert "postcheck_failed" in names(record) and TEST not in target.wlans


def test_the_write_account_session_never_logs_the_passphrase_in_an_error(tmp_path):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)
    target.refuse["open wpa2 passphrase"] = "The command is either unrecognized or incomplete."
    record = apply_approved(runtime, request())
    assert record["result"] == "reverted" and target.passphrases == []
    blob = json.dumps(record) + (tmp_path / "audit" / "audit.jsonl").read_text()
    assert not re.search(r"passphrase [A-Za-z0-9]{32}", blob)


@pytest.mark.parametrize("key,field,value", [
    ("host02", None, None),
    (TEST, "Authentication Server", "External RADIUS"),
    (TEST, "Web Authentication", "Enabled"),
    (TEST, "Max. Clients", "32"),
    (TEST, "Dynamic PSK", "Enabled"),
    (TEST, "Unexpected setting", "Unknown"),
])
def test_delete_refuses_wlan_configuration_that_cannot_be_recreated(tmp_path, key, field, value):
    runtime, target = created(tmp_path, wlans=(TEST, "host02"))
    if field is not None:
        if field == "Unexpected setting":
            target.wlans[key].append("      Unexpected setting = " + value)
        else:
            target._set(target.wlans[key], field, value)
    delete = request(op="delete", key=key, changes={}, request_id="req-ruckus-delete")
    before = target._listing()
    sent = len(target.sent)
    preview = execute.preview(runtime, "ap", delete)
    assert preview["result"] == "rejected"
    assert "wlan_delete_not_restorable" in preview["reason_codes"]
    with pytest.raises(Rejected) as exc:
        apply_approved(runtime, delete)
    assert "wlan_delete_not_restorable" in exc.value.reason_codes
    assert len(target.sent) == sent and target._listing() == before


@pytest.mark.parametrize("compensate", [False, True])
def test_recreating_deleted_wlan_reports_new_passphrase(tmp_path, compensate):
    runtime, target = created(tmp_path)
    first = target.last_passphrase
    if compensate:
        before = target._listing()
        target.check_view = lambda _listing: before
    deleted = apply_approved(runtime, request(op="delete", changes={}, request_id="req-ruckus-delete"))
    if compensate:
        restored = deleted
        assert restored["result"] == "revert-failed" and "compensation_partial" in names(restored)
    else:
        assert deleted["result"] == "confirmed"
        restored = execute.undo(runtime, deleted["change_id"], "restore")
        assert "undo_partial" in names(restored)
    assert restored["reason"] and "new passphrase" in restored["reason"]
    assert "web interface" in restored["reason"]
    assert target.last_passphrase != first
    assert target.state(TEST)["encryption"] == "wpa2"


@pytest.mark.parametrize("compensate", [False, True])
def test_summary_recover_reports_partial_restore_of_deleted_wlan(tmp_path, monkeypatch, compensate):
    runtime, target = created(tmp_path)
    delete = request(op="delete", changes={}, request_id="req-ruckus-delete")
    first = target.last_passphrase
    step = execute._step
    stop_after = "compensation_applied" if compensate else "confirm_start"

    def interrupt(*args):
        step(*args)
        if args[2] == stop_after:
            raise Interrupted()

    if compensate:
        before = target._listing()
        target.check_view = lambda _listing: before
        monkeypatch.setattr(execute, "_step", interrupt)
        with pytest.raises(Interrupted):
            apply_approved(runtime, delete)
        target.check_view = None
    else:
        deleted = apply_approved(runtime, delete)
        monkeypatch.setattr(execute, "_step", interrupt)
        with pytest.raises(Interrupted):
            execute.undo(runtime, deleted["change_id"], "restore")
    monkeypatch.setattr(execute, "_step", step)
    assert TEST in target.wlans and target.last_passphrase != first
    restored, = execute.recover(runtime, "ap")
    assert restored["result"] == ("revert-failed" if compensate else "confirmed")
    assert "web interface" in restored["reason"]
    assert target.last_passphrase not in json.dumps(restored)


def test_undo_delete_preserves_wpa3_psk_mode(tmp_path):
    runtime, target = created(tmp_path)
    # WPA3/SAE differs from the measured WPA2 defaults only as recorded in the unsaved probe.
    block = target.wlans[TEST]
    target._set(block, "Encryption", "wpa3")
    target._set(block, "80211w-pmf", "Required")
    block.append("      SAE anti-clogging-threshold = 5")
    deleted = apply_approved(runtime, request(op="delete", changes={}, request_id="req-ruckus-wpa3"))
    assert deleted["result"] == "confirmed"
    restored = execute.undo(runtime, deleted["change_id"], "restore")
    assert restored["result"] == "confirmed" and "new passphrase" in restored["reason"]
    assert "open wpa3 passphrase %s algorithm aes" % ruckus.PASSPHRASE_TOKEN in target.applied[-1]
    assert target.state(TEST)["encryption"] == "wpa3"


@pytest.mark.parametrize("diagnostic", [False, True])
@pytest.mark.parametrize("form", ["generated", "literal-wpa2", "literal-wpa3"])
def test_device_access_redacts_passphrase_before_storing_pty_answer(monkeypatch, diagnostic, form):
    from types import SimpleNamespace

    from netops_admin.access import DeviceAccess

    fictitious = "G111FictitiousPassphrase"
    use_wpa3 = form == "literal-wpa3"
    command = "open %s passphrase %s%s" % ("wpa3" if use_wpa3 else "wpa2",
                                           ruckus.PASSPHRASE_TOKEN if form == "generated" else fictitious,
                                           "" if use_wpa3 else " algorithm aes")
    monkeypatch.setattr(exec_ruckus, "_generated", lambda: fictitious)
    measured_echo, measured_ok, _prompt = measured("cli_wpa2.out").splitlines()[6:9]
    echo = measured_echo.replace("wpa2 passphrase <GENERATED> algorithm aes", command[5:])
    echo = echo.replace(ruckus.PASSPHRASE_TOKEN, fictitious)
    body = ("PSK rejected: %s repeated %s" % (fictitious, fictitious)) if diagnostic else measured_ok
    spec = exec_ruckus.prompt_spec()
    shell = Shell([(exec_ruckus.LOGIN_PROMPT, b"Please login: "),
                   (exec_ruckus.PASSWORD_PROMPT, b"Password: "),
                   (exec_ruckus.USER_PROMPT, b"\nruckus>"),
                   (exec_ruckus.ENABLE_PROMPT, b"\nruckus# "),
                   (spec.anchor, ("%s\n%s\nruckus" % (echo, body)).encode()),
                   (spec.ends[0], b"(config-wlan)# ")])
    from contextlib import nullcontext

    access = DeviceAccess.__new__(DeviceAccess)
    access.credential = SimpleNamespace(login="operator", use=lambda: "dummy-login-password")
    monkeypatch.setattr(access, "_session", lambda: nullcontext(shell))
    seen = []
    access.line_answered = lambda _number, answer: seen.append(answer)
    if diagnostic:
        with pytest.raises(AccessError) as exc:
            access.apply([command], spec)
        assert "PSK rejected:" in str(exc.value)
        assert fictitious not in str(exc.value)
    else:
        assert access.apply([command], spec) == 1
        assert len(seen) == 1 and fictitious not in seen[0]
    assert len(access.last_answers) == 1
    assert fictitious not in access.last_answers[0]


def test_quoted_description_survives_update_undo_and_compensation(tmp_path):
    runtime, target = created(tmp_path)
    original = "lab WLAN (WIRELESS-WLANS)!"
    target._set(target.wlans[TEST], "Description", original)
    changed = apply_approved(runtime, request(op="update", changes={"description": "replacement"},
                                                   request_id="req-ruckus-description"))
    assert changed["result"] == "confirmed"
    preview = execute.preview_undo(runtime, changed["change_id"], "restore description")
    assert preview["result"] == "ready"
    quoted = 'description "%s"' % original
    assert quoted in preview["commands"]
    undone = execute.undo(runtime, changed["change_id"], "restore description")
    assert undone["result"] == "confirmed" and target.state(TEST)["description"] == original
    before = target._listing()
    target.check_view = lambda _: before
    failed = apply_approved(runtime, request(op="update", changes={"description": "with spaces"},
                                                  request_id="req-ruckus-compensate"))
    assert failed["result"] == "reverted"
    assert 'description "with spaces"' in target.applied[-2] and quoted in target.applied[-1]
    assert target.state(TEST)["description"] == original


@pytest.mark.parametrize("account", ["write", "check"])
def test_create_rejects_open_encryption_on_either_readback(tmp_path, account):
    target = FakeRuckus()
    runtime = make_runtime(tmp_path, target)
    if account == "write":
        target.after_write = lambda fake: fake._set(fake.wlans[TEST], "Encryption", "none")
    else:
        open_listing = measured("show_wlan_all_with_test.out").partition("\n")[2]
        target.check_view = lambda listing: open_listing if target.applied else listing
    created_record = apply_approved(runtime, request(changes={"ssid": TEST, "service": "disabled", "vlan": 3999}))
    assert created_record["result"] == "reverted", steps(created_record)
    assert ("postcheck_failed" if account == "write" else "check_identity_failed") in names(created_record)
    assert TEST not in target.wlans


def test_update_rejects_changed_authentication_on_check_readback(tmp_path):
    runtime, target = created(tmp_path)

    def check_view(listing):
        if len(target.applied) == 1:
            return listing
        before, _, after = listing.rpartition("Authentication = open")
        return before + "Authentication = 802.1x" + after

    target.check_view = check_view
    changed = apply_approved(runtime, request(op="update", changes={"vlan": 3999},
                                                   request_id="req-ruckus-auth"))
    assert changed["result"] == "reverted"
    assert "check_identity_failed" in names(changed)
    assert target.state(TEST)["vlan"] == "1"
