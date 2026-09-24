import json
import pytest
from netops_admin import audit, execute, exec_exos
from test_execute import make_runtime, request
from fake_fortios import FakeFortiOS
from fake_exos import FakeExos
from test_execute_exos import make_runtime as exos_runtime, request as exos_request


@pytest.mark.parametrize("updates", [
    {"updated_at": float("nan")}, {"updated_at": float("inf")}, {"updated_at": 200},
    {"pending": -1}, {"pending": 1.5}, {"pending": True}, {"oldest_pending_age_seconds": float("nan")},
    {"oldest_pending_age_seconds": -1},
])
def test_malformed_export_status_cannot_unlock_writes(tmp_path, updates):
    from netops_admin.config import DEFAULT_LIMITS
    path = tmp_path / "export.json"
    path.write_text(json.dumps(dict({"updated_at": 100, "pending": 0}, **updates)))
    assert audit.export_state(path, DEFAULT_LIMITS, clock=lambda: 100)[0] == "blocked"


def test_notification_exception_is_durable_and_blocks_next_write(tmp_path):
    target = FakeFortiOS()
    runtime = make_runtime(tmp_path, target)
    def broken(_record):
        raise RuntimeError("transport unavailable")
    runtime.notifier = broken
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "confirmed" and record["notification"] == "failed"
    from netops_admin.errors import Rejected
    with pytest.raises(Rejected, match="notification"):
        execute.apply(runtime, "lab", request(request_id="after-failure", key="another"))


@pytest.mark.parametrize("save_fails", [False, True])
def test_recover_confirmation_must_save_the_restored_configuration(tmp_path, monkeypatch, save_fails):
    target = FakeExos()
    runtime = exos_runtime(tmp_path, target)
    original = execute._persist
    class Crash(BaseException):
        pass
    def interrupted(*args):
        raise Crash()
    monkeypatch.setattr(execute, "_persist", interrupted)
    with pytest.raises(Crash):
        execute.apply(runtime, "sw", exos_request())
    monkeypatch.setattr(execute, "_persist", original)
    calls = []
    def save(*args):
        calls.append(True)
        if save_fails:
            raise RuntimeError("save failed")
        return True
    monkeypatch.setattr(exec_exos, "persist", save)
    record = execute.recover(runtime, "sw")[0]
    assert calls and record["result"] == "confirmed"
    if save_fails:
        assert record["reason"] == "not persisted"
        assert runtime.store.blocked("sw")

def test_randomized_secret_ciphertext_does_not_hide_structural_or_admin_changes():
    from netops_admin.fortios import Snapshot
    header = "#config-version=FGT60F-7.6.7-FW-build3704-260601:opmode=0:vdom=0\n"
    original = header + 'config vpn certificate local\nedit example\nset password ENC synthetic-a\nset comments original\nnext\nend\n'
    digest = lambda text: Snapshot(text).rest_digest("firewall address", "not-present")
    assert digest(original) == digest(original.replace("synthetic-a", "synthetic-b"))
    assert digest(original) != digest(original.replace("comments original", "comments changed"))
    assert digest(original) != digest(original.replace("set password ENC synthetic-a\n", ""))
    admin = original.replace("vpn certificate local", "system admin")
    assert digest(admin) != digest(admin.replace("synthetic-a", "synthetic-b"))

def test_exos_absence_requires_complete_inventory_when_detail_is_ambiguous():
    from netops_admin import exos
    text = "Name VID Protocol Addr Flags Ports\nusers 20 --- ANY 0 /0 VR-Default\nTotal number of VLAN(s) : 1\n"
    assert exos.vlan_absent_from_list(text, "guest")
    assert not exos.vlan_absent_from_list(text, "users")
    assert not exos.vlan_absent_from_list(text.replace(": 1", ": 2"), "guest")
    assert not exos.vlan_absent_from_list("Permission denied", "guest")

def test_live_grouping_syntax_protects_lag_members_and_allows_an_unrelated_port(tmp_path):
    from netops_admin import membership, exos
    from test_operations_020 import runtime_for
    runtime, target, name = runtime_for(tmp_path, "exos")
    text = target.snapshot() + "\nenable sharing 12 grouping 12-13 algorithm address-based L3_L4 lacp\n"
    snapshot = exos.Snapshot(text, "33.7.1.6")
    before = {"untagged": "users", "tagged": "guest"}
    assert membership.prechecks(snapshot, "10", before, dict(before, untagged="staging")) == []
    text = text.replace("ports 10", "ports 12")
    snapshot = exos.Snapshot(text, "33.7.1.6")
    assert "aggregation" in membership.prechecks(snapshot, "12", before, dict(before, untagged="staging"))[0]


def test_large_member_list_is_bounded_in_the_exported_audit():
    from netops_admin import audit
    from netops_admin.profiles import find_profile
    profile = find_profile("fortios", "firewall addrgrp", "7.6.7 build3704")
    value = " ".join("host-%03d" % n for n in range(128))
    assert audit.summarized_changes(profile, {"member": value}) == {"member": "128 object names"}

def test_membership_table_with_standalone_untagged_column_header():
    from netops_admin.membership import shown
    text = "         Untagged  \nPort     /Tagged   VLAN Name(s)\n-------- --------  ---------------\n10       Untagged  users\n"
    assert shown(text, "10") == {"untagged": "users", "tagged": ""}

def test_foreign_ordered_policy_tables_are_not_sorted_away():
    from netops_admin.fortios import Snapshot
    header = "#config-version=FGT60F-7.6.7-FW-build3704-260601:opmode=0:vdom=0\n"
    first = "edit 1\nset action accept\nnext\n"
    second = "edit 2\nset action deny\nnext\n"
    def digest(rows):
        text = header + "config firewall local-in-policy\n" + rows + "end\n"
        return Snapshot(text).rest_digest("firewall address", "unused")
    assert digest(first + second) != digest(second + first)

def test_access_profile_permissions_are_part_of_the_enrollment_identity():
    from netops_admin.fortios import admin_fingerprint
    from netops_admin.errors import Rejected
    admins = 'config system admin\nedit example\nset accprofile operator-example\nnext\nend\n'
    profile = 'config system accprofile\nedit operator-example\nset netgrp read\nnext\nend\n'
    assert admin_fingerprint(admins, profile) != admin_fingerprint(admins, profile.replace("netgrp read", "netgrp read-write"))
    with pytest.raises(Rejected, match="profile"):
        admin_fingerprint(admins, "")

def test_upm_membership_must_restore_persistable_state_not_only_live_state(tmp_path, monkeypatch):
    from netops_admin import execute, exos, engine
    from test_operations_020 import runtime_for, request
    runtime, target, name = runtime_for(tmp_path, "exos")
    monkeypatch.setattr(exos, "safeguard_script", lambda inverse: list(inverse))
    def fail_after_change(fake, _lines):
        if len(fake.applied_blocks) == 2:
            fake.check_unreadable = True
    target.on_apply = fail_after_change
    record = execute.apply(runtime, name, request("vlan-membership", "10", {"untagged": "staging", "tagged": []}))
    assert record["result"] == "revert-failed"
    assert target.memberships["10"]["untagged"] == "users"
    assert not engine.verify(record["plan"], target.snapshot().encode(), expect="before")["object_matches"]

def test_partial_native_move_still_attempts_every_inverse_command(tmp_path):
    from netops_admin import execute, engine
    from test_operations_020 import runtime_for, request
    runtime, target, name = runtime_for(tmp_path, "exos")
    def partial(fake, lines):
        if len(fake.applied_blocks) == 2:
            fake.fail_at_line = 2
        else:
            fake.fail_at_line = None
    target.on_apply = partial
    record = execute.apply(runtime, name, request("vlan-membership", "10", {"untagged": "staging", "tagged": ["guest", "users"]}))
    assert record["result"] == "reverted"
    assert engine.verify(record["plan"], target.snapshot().encode(), expect="before")["result"] == "match"
