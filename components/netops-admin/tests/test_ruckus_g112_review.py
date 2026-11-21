"""Regressions for the blocking G112 review findings, using the Admin engine and measured Unleashed CLI."""
from __future__ import annotations

import re
import secrets

import pytest

from netops_admin import execute, ruckus
from netops_admin.errors import Rejected
from test_ruckus_g111 import TEST, Interrupted, request
from test_ruckus_g112 import RELAY, apply_approved, fixture, lab, personal, relay_request


@pytest.mark.parametrize("changes", [
    {"vlan": 5}, {"ssid": "changed-ssid"}, {"service": "disabled"},
    {"isolation-ap": "enabled"}, {"l2acl": "allow-list"},
])
def test_active_wlan_requires_and_accepts_impact(tmp_path, changes):
    runtime, target = lab(tmp_path, wlans=(TEST, RELAY, "host01"))
    fields = dict(op="update", key="host01", changes=changes, request_id="review-wlan-impact")
    before = len(target.sent)
    refused = execute.preview(runtime, "ap", request(**fields))
    assert refused.get("reason_codes") == ["endpoint_impact_required"]
    preview = execute.preview(runtime, "ap", request(**fields, endpoint_impact="host01"))
    assert preview["result"] == "ready"
    assert any("Explicit endpoint impact accepted for WLAN host01" in check for check in preview["prechecks"])
    assert len(target.sent) == before


@pytest.mark.parametrize("op,changes", [
    ("create", {"ssid": "review-disabled", "service": "disabled"}),
    ("update", {"description": "review"}),
    ("delete", {}),
])
def test_plain_wlan_apply_requires_hash(tmp_path, op, changes):
    key = "review-disabled" if op == "create" else TEST
    runtime, target = lab(tmp_path, wlans=(TEST, RELAY, "review-disabled"))
    req = request(op=op, key=key, changes=changes, request_id="review-missing-hash")
    assert execute.preview(runtime, "ap", req)["result"] == "ready"
    before = len(target.sent)
    with pytest.raises(Rejected) as exc:
        execute.apply(runtime, "ap", req)
    assert exc.value.reason_codes == ["plan_changed"]
    assert len(target.sent) == before


@pytest.mark.parametrize("mode", ["wpa2", "wpa3"])
def test_public_psk_reference_cannot_be_null(tmp_path, mode):
    runtime, target = lab(tmp_path)
    before = len(target.sent)
    preview = execute.preview(runtime, "ap", personal(mode, ref=None))
    assert preview["result"] == "rejected"
    assert any("passphrase-ref" in reason for reason in preview["reasons"])
    assert len(target.sent) == before


def test_unsetting_inactive_auth_server_does_not_generate_passphrase(tmp_path):
    runtime, _ = lab(tmp_path)
    req = request(op="update", request_id="review-clear-inactive-auth-server",
                  changes={"authentication": "open", "encryption": "wpa2", "auth-server": None,
                           "description": "new description"})
    preview = execute.preview(runtime, "ap", req)
    assert preview["result"] == "ready"
    assert preview["commands"] == ["config", "wlan " + TEST, 'description "new description"', "end", "exit"]


def test_create_reports_generated_passphrase(tmp_path):
    key = "review-generated"
    runtime, _ = lab(tmp_path, wlans=(TEST, RELAY, key))
    record = apply_approved(runtime, request(key=key, changes={"ssid": key, "service": "disabled"},
                                             request_id="review-generated"))
    assert record["result"] == "confirmed"
    assert "generated" in (record.get("reason") or "") and "clients" in record["reason"]


@pytest.mark.parametrize("failure", ["check-down", "interrupted", "masked", "different"])
def test_psk_only_write_without_secret_readback_is_unknown(tmp_path, failure):
    runtime, target = lab(tmp_path)
    req = personal("wpa2")
    preview = execute.preview(runtime, "ap", req)
    assert preview["result"] == "ready"
    assert preview["predicted"]["before"] == preview["predicted"]["after"]
    original_check = target.check_query
    original_apply_count = len(target.applied)

    def check_query(command):
        if len(target.applied) > original_apply_count:
            if failure == "interrupted":
                raise Interrupted()
            if failure == "check-down":
                raise RuntimeError("check account unavailable")
            shown = "<redacted>" if failure == "masked" else secrets.token_hex(16)
            return re.sub(r"(?m)^(      Passphrase\s*= ).*$",
                          lambda match: match[1] + shown, original_check(command))
        return original_check(command)

    target.check_query = check_query
    if failure == "interrupted":
        with pytest.raises(Interrupted):
            execute.apply(runtime, "ap", req, expected_plan_sha256=preview["plan_sha256"])
        target.check_query = original_check
        record, = execute.recover(runtime, "ap")
    else:
        record = execute.apply(runtime, "ap", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "unknown"
    assert "passphrase" in record["reason"].lower() and "may" in record["reason"]
    assert len(target.applied) == original_apply_count + 1


@pytest.mark.parametrize("failure", ["disconnect", "interrupted", "read-unavailable"])
def test_relay_update_restores_profile_deleted_before_replacement(tmp_path, failure):
    listing = fixture("cli_dhcp_update.out").split("ruckus# show dhcp all\n", 1)[1].split("ruckus# config", 1)[0]
    measured = ruckus.parse_relays(listing)
    key = "netops-g112-d2"
    assert "The DHCP server '%s' has been deleted." % key in fixture("cli_dhcp_update.out")
    assert "The DHCP server 'nonexistent-x' could not be found." in fixture("cli_dhcp.out")
    runtime, target = lab(tmp_path, wlans=(TEST, key))
    for name, state in measured.items():
        target.relays[name] = {"description": state["description"], "addresses": [state["first"], state["second"]]}
    previous = target.relays.copy()
    req = relay_request("update", key=key, first="192.0.2.78")
    preview = execute.preview(runtime, "ap", req)
    assert preview["result"] == "ready"
    original = target.apply

    def apply_then_disconnect(commands, spec):
        target.apply = original
        assert commands[:2] == ["config", "no dhcp " + key]
        if failure == "interrupted":
            original(commands[:2], spec)
            raise Interrupted()
        target.stop_after = 2
        try:
            return original(commands, spec)
        finally:
            target.stop_after = None
            target.dhcp_unreadable = failure == "read-unavailable"

    target.apply = apply_then_disconnect
    if failure == "interrupted":
        with pytest.raises(Interrupted):
            execute.apply(runtime, "ap", req, expected_plan_sha256=preview["plan_sha256"])
        assert key not in target.relays
        record, = execute.recover(runtime, "ap")
        assert execute.recover(runtime, "ap") == []
    else:
        record = execute.apply(runtime, "ap", req, expected_plan_sha256=preview["plan_sha256"])
        if failure == "read-unavailable":
            assert key not in target.relays and record["result"] == "unknown"
            assert "relay_recovery_pending" in {step["step"] for step in record["steps"]}
            writes = list(target.applied)
            pending, = execute.recover(runtime, "ap")
            assert pending["change_id"] == record["change_id"] and pending["result"] == "unknown"
            assert [step["step"] for step in pending["steps"][-2:]] == ["recovery_start", "recovery_access_failed"]
            assert runtime.store.blocked("ap")["change_id"] == pending["change_id"]
            assert target.applied == writes and key not in target.relays
            target.dhcp_unreadable = False
            record, = execute.recover(runtime, "ap")
            assert execute.recover(runtime, "ap") == []
    assert record["result"] == "reverted"
    assert target.relays == previous
    assert target.applied[-1][:2] == ["config", "dhcp " + key]
