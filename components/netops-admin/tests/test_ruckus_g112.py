"""1.0.12 G112 (R06, R22, R23, R24): WPA2/WPA3 passphrase by vault reference or enterprise server, MAC/L3 ACL, client
isolation, client and rate limits of a Ruckus Unleashed WLAN and its DHCP relay server entries, through the common Admin
engine, against the measured answers of the lab R610 (200.15.6.212 build 27, tests/fixtures/ruckus_g112).
"""
from __future__ import annotations

import json
import re
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_ruckus import FIXTURES, FakeRuckus
from test_ruckus_g111 import TEST, Interrupted, Shell, created, make_runtime, names, request, steps

from netops_admin import exec_ruckus, execute, ruckus
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile
from netops_admin.request import parse_request

G112 = FIXTURES.parent / "ruckus_g112"
REF = "WLAN_PSK_LAB"
SECRET = "Fictitious-Passphrase-G112"
RELAY = "relay-g112"


def fixture(name):
    return (G112 / name).read_text(encoding="utf-8")


def shows():
    """The `show` listings of the unsaved test WLAN in the order of cli_wlan.out, each as a one-WLAN listing."""
    parts = re.split(r"ruckus\(config-wlan\)# show\n", fixture("cli_wlan.out"))
    return [part.split("ruckus(")[0] for part in parts[1:]]


def wlan(text):
    snapshot = ruckus.parse_listing(ruckus.redact(text))
    return next(iter(snapshot.entries("wlan").values()))


def apply_approved(runtime, req):
    preview = execute.preview(runtime, "ap", req)
    assert preview["result"] == "ready", preview
    return execute.apply(runtime, "ap", req, expected_plan_sha256=preview["plan_sha256"])


def update(**changes):
    changes = {name.replace("_", "-"): value for name, value in changes.items()}
    suffix = request.counter = getattr(request, "counter", 0) + 1
    return request(op="update", changes=changes, request_id="req-g112-%04d" % suffix)


def relay_request(op, key=RELAY, **changes):
    suffix = request.counter = getattr(request, "counter", 0) + 1
    return request(table="dhcp-relay", op=op, key=key, changes=changes, request_id="req-g112-%04d" % suffix)


def lab(tmp_path, **kwargs):
    kwargs.setdefault("wlans", (TEST, RELAY))
    runtime, target = created(tmp_path, **kwargs)
    runtime.config.limits.update(changes_per_device_per_hour=1000, changes_per_day=1000)
    target.vault[REF] = SECRET
    return runtime, target


# --- the measured answers ---------------------------------------------------------------------------------------------

def test_fake_answers_of_g112_are_measured_ones():
    import fake_ruckus
    transcript = fixture("cli_wlan.out") + fixture("cli_wlan_errors.out") + fixture("cli_dhcp.out")
    for text in (fake_ruckus.MAX_CLIENTS_REFUSED, fake_ruckus.RATE_REFUSED, fake_ruckus.PERSSID_REFUSED):
        assert text in transcript, text
    for text in ("The RADIUS server 'nonexistent-aaa' could not be found.", "The L2 ACL 'nonexistent-x' could not be found.",
                 "The L3/L4/IP ACL 'nonexistent-x' could not be found.", "The IP address is invalid.",
                 "The DHCP server 'netops-g112-dhcp2' has been deleted."):
        assert text in transcript, text


def test_measured_listing_states_are_read_back_as_profile_attributes():
    baseline, limits, defaults, dot1x, personal_stale, dot1x_wpa3, personal_wpa3 = shows()[:7]
    assert wlan(baseline).attributes == {"ssid": "ssid01", "vlan": "1", "service": "disabled",
                                         "authentication": "open", "encryption": "none"}
    assert wlan(limits).attributes == {
        "ssid": "ssid01", "vlan": "1", "service": "disabled", "authentication": "open", "encryption": "none",
        "max-clients": "37", "isolation-ap": "enabled", "l2acl": "netops-g112-acl", "l3acl": "netops-g112-l3",
        "rate-perssid-uplink": "10", "rate-perssid-downlink": "20", "rate-uplink": "5", "rate-downlink": "6"}
    assert wlan(defaults).attributes == wlan(baseline).attributes
    assert wlan(dot1x).attributes["authentication"] == "dot1x"
    assert wlan(dot1x).attributes["auth-server"] == "netops-g112-aaa" and wlan(dot1x).attributes["encryption"] == "wpa2"
    # measured: a personal passphrase after enterprise authentication keeps the old server name in the listing
    assert wlan(personal_stale).attributes["authentication"] == "open"
    assert "auth-server" not in wlan(personal_stale).attributes
    assert wlan(dot1x_wpa3).attributes["encryption"] == "wpa3" and wlan(personal_wpa3).attributes["encryption"] == "wpa3"
    assert not any(wlan(text).unsupported for text in (baseline, limits, defaults, dot1x, personal_stale))


def test_measured_relay_listing_is_parsed_and_an_incomplete_one_is_not():
    listing = fixture("cli_dhcp.out").partition("ruckus# show dhcp all\n")[2].split("ruckus#")[0]
    assert ruckus.parse_relays(listing) == {"netops-g112-dhcp": {"first": "192.0.2.53", "second": "192.0.2.54",
                                                                  "description": "relay-test"}}
    empty = (G112.parents[3] / "netops-helper" / "tests" / "fixtures" / "ruckus_g110" / "show_dhcp_all.out")
    assert ruckus.parse_relays(empty.read_text().partition("\n")[2].split("ruckus#")[0]) == {}
    assert ruckus.parse_relays("DHCP servers for DHCP relay agent:\n  ID:\n    1:\n      Name= x\n") is None
    assert ruckus.parse_relays("DHCP servers for DHCP relay agent:\n  ID:\n    1:\n      Name= x\n"
                               "      IP Address= 192.0.2.1\n      Surprise= y\n") is None
    assert ruckus.parse_relays("something else") is None


@pytest.mark.parametrize("field,value", [("PerSSID Rate Limiting Uplink", "5.5"), ("Rate Limiting Uplink", "0.50Mbps"),
                                         ("Max. Clients", "many"), ("Isolation per AP", "Maybe")])
def test_a_value_the_profile_cannot_write_back_is_outside_the_profile(tmp_path, field, value):
    runtime, target = lab(tmp_path)
    target._set(target.wlans[TEST], field, value)
    preview = execute.preview(runtime, "ap", update(max_clients=40))
    assert preview["result"] == "rejected" and "outside the profile" in " ".join(preview["reasons"])


# --- R22 / R24: ACL, isolation and limits ----------------------------------------------------------------------------

ALL = {"max-clients": 37, "isolation-ap": "enabled", "l2acl": "allow-list", "l3acl": "guest-l3",
       "rate-perssid-uplink": 10, "rate-perssid-downlink": 20, "rate-uplink": 5, "rate-downlink": 6}


def test_preview_shows_the_commands_and_writes_nothing(tmp_path):
    runtime, target = lab(tmp_path)
    sent = len(target.sent)
    preview = execute.preview(runtime, "ap", update(**ALL))
    assert preview["result"] == "ready", preview
    assert preview["commands"] == [
        "config", "wlan " + TEST, "max-clients 37", "client-isolation isolation-on-ap enable", "acl l2acl allow-list",
        "acl l3acl guest-l3", "rate-limit perssid_uplink 10", "rate-limit perssid_downlink 20",
        "rate-limit uplink 5 downlink 6", "end", "exit"]
    assert preview["predicted"]["after"] == {
        "ssid": TEST, "service": "disabled", "authentication": "open", "encryption": "wpa2",
        "max-clients": "37", "isolation-ap": "enabled", "l2acl": "allow-list", "l3acl": "guest-l3",
        "rate-perssid-uplink": "10", "rate-perssid-downlink": "20", "rate-uplink": "5", "rate-downlink": "6"}
    assert target.applied[1:] == [] and len(target.sent) == sent and "endpoint_impact" not in preview


def test_confirmed_apply_reads_back_and_the_undo_restores_the_exact_listing(tmp_path):
    runtime, target = lab(tmp_path)
    before = list(target.wlans[TEST])
    record = apply_approved(runtime, update(**ALL))
    assert record["result"] == "confirmed", (steps(record), record.get("postcheck_differences"))
    values = target.values(TEST)
    assert (values["Max. Clients"], values["Isolation per AP"], values["L2/MAC"], values["L3/L4/IP Address"]) == (
        "37", "Enabled", "allow-list", "guest-l3")
    assert (values["PerSSID Rate Limiting Uplink"], values["PerSSID Rate Limiting Downlink"],
            values["Rate Limiting Uplink"], values["Rate Limiting Downlink"]) == ("10", "20", "5.00Mbps", "6.00Mbps")
    assert "postcheck_passed" in names(record) or "check_identity_passed" in names(record)
    undone = execute.undo(runtime, record["change_id"], "back")
    assert undone["result"] == "confirmed", steps(undone)
    assert target.wlans[TEST] == before
    assert target.applied[-1] == ["config", "wlan " + TEST, "max-clients 100", "client-isolation isolation-on-ap disable",
                                  "no l2acl", "no l3acl", "rate-limit perssid_uplink 0", "rate-limit perssid_downlink 0",
                                  "no rate-limit", "end", "exit"]


def test_a_changed_acl_is_restored_to_the_previous_one_not_removed(tmp_path):
    runtime, target = lab(tmp_path)
    apply_approved(runtime, update(l2acl="allow-list", rate_uplink=5, rate_downlink=6))
    changed = apply_approved(runtime, update(l2acl="block-list", rate_uplink=9, rate_downlink=8))
    assert changed["result"] == "confirmed"
    execute.undo(runtime, changed["change_id"], "back")
    values = target.values(TEST)
    assert values["L2/MAC"] == "allow-list" and values["Rate Limiting Uplink"] == "5.00Mbps"
    assert values["Rate Limiting Downlink"] == "6.00Mbps"


def test_removing_an_acl_and_the_per_client_limit_uses_the_no_commands(tmp_path):
    runtime, target = lab(tmp_path)
    apply_approved(runtime, update(l2acl="allow-list", l3acl="guest-l3", rate_uplink=5, rate_downlink=6))
    removed = apply_approved(runtime, update(l2acl=None, l3acl=None, rate_uplink=None, rate_downlink=None))
    assert removed["result"] == "confirmed", steps(removed)
    assert target.applied[-1] == ["config", "wlan " + TEST, "no l2acl", "no l3acl", "no rate-limit", "end", "exit"]
    assert target.values(TEST)["L2/MAC"] == "No ACLS" and target.values(TEST)["Rate Limiting Uplink"] == "Disabled"


@pytest.mark.parametrize("changes,why", [
    ({"rate-uplink": 5}, "together"),
    ({"rate-downlink": 5}, "together"),
    ({"max-clients": 513}, "1..512"),
    ({"max-clients": 0}, "1..512"),
    ({"rate-perssid-uplink": 501}, "0..500"),
    ({"isolation-ap": "maybe"}, "must match"),
    ({"l2acl": "bad name"}, "must match"),
    ({"passphrase": "x"}, "not in the profile"),
])
def test_invalid_values_are_refused_before_any_device_contact(tmp_path, changes, why):
    runtime, target = lab(tmp_path)
    sent = len(target.sent)
    preview = execute.preview(runtime, "ap", update(**changes))
    assert preview["result"] == "rejected" and why in " ".join(preview["reasons"])
    assert len(target.sent) == sent


def test_unknown_acl_is_refused_by_the_device_and_nothing_is_saved(tmp_path):
    runtime, target = lab(tmp_path)
    before = list(target.wlans[TEST])
    record = apply_approved(runtime, update(l2acl="no-such-acl"))
    assert record["result"] == "reverted", steps(record)
    assert target.wlans[TEST] == before and "compensation_not_needed" in names(record)


def test_a_g112_apply_without_the_approved_plan_hash_is_refused(tmp_path):
    runtime, target = lab(tmp_path)
    with pytest.raises(Rejected) as err:
        execute.apply(runtime, "ap", update(max_clients=37))
    assert err.value.reason_codes == ["plan_changed"]
    with pytest.raises(Rejected) as err:
        execute.apply(runtime, "ap", relay_request("create", first="192.0.2.10"))
    assert err.value.reason_codes == ["plan_changed"]
    assert len(target.applied) == 1  # only the creation of the test WLAN


def test_a_changed_listing_after_the_preview_invalidates_the_approved_hash(tmp_path):
    runtime, target = lab(tmp_path)
    req = update(max_clients=37)
    approved = execute.preview(runtime, "ap", req)["plan_sha256"]
    target._set(target.wlans[TEST], "VLAN-ID", "77")
    with pytest.raises(Rejected) as err:
        execute.apply(runtime, "ap", req, expected_plan_sha256=approved)
    assert err.value.reason_codes == ["plan_changed"]


def test_a_new_wlan_is_not_created_with_g112_attributes(tmp_path):
    runtime, target = lab(tmp_path)
    preview = execute.preview(runtime, "ap", request(op="create", key="netops-g112-b", request_id="req-g112-create",
                                                      changes={"ssid": "netops-g112-b", "service": "disabled",
                                                               "max-clients": 10}))
    assert preview["result"] == "rejected"


def test_a_wlan_that_is_not_selected_is_not_changed_by_g112_either(tmp_path):
    runtime, target = lab(tmp_path)
    preview = execute.preview(runtime, "ap", request(op="update", key="host02", changes={"max-clients": 10},
                                                      request_id="req-g112-host02"))
    assert preview["reason_codes"] == ["wlan_not_selected"]


# --- endpoint impact on a WLAN that broadcasts --------------------------------------------------------------------------

def test_a_broadcasting_wlan_needs_the_explicit_endpoint_impact(tmp_path):
    runtime, target = lab(tmp_path, wlans=(TEST, RELAY, "host01"))
    req = request(op="update", key="host01", changes={"max-clients": 50}, request_id="req-g112-active")
    refused = execute.preview(runtime, "ap", req)
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["endpoint_impact_required"]
    accepted = request(op="update", key="host01", changes={"max-clients": 50}, request_id="req-g112-active2",
                       endpoint_impact="host01")
    preview = execute.preview(runtime, "ap", accepted)
    assert preview["result"] == "ready", preview
    assert any("clients may lose access" in item for item in preview["prechecks"])
    record = execute.apply(runtime, "ap", accepted, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", steps(record)
    assert runtime.store.operation(record["change_id"])["plan"]["endpoint_impact"] == "host01"
    assert target.values("host01")["Max. Clients"] == "50"
    undone = execute.undo(runtime, record["change_id"], "back")
    assert undone["result"] == "confirmed" and target.values("host01")["Max. Clients"] == "100"


def test_disabled_wlan_updates_and_active_description_need_no_impact(tmp_path):
    runtime, target = lab(tmp_path, wlans=(TEST, RELAY, "host01"))
    assert execute.preview(runtime, "ap", update(max_clients=50, vlan=5))["result"] == "ready"
    plain = request(op="update", key="host01", changes={"description": "new label"}, request_id="req-g112-plain")
    assert execute.preview(runtime, "ap", plain)["result"] == "ready"


def test_summary_undo_of_enabling_wlan_binds_impact_to_the_preview(tmp_path):
    runtime, target = lab(tmp_path)
    before = target._listing()
    record = apply_approved(runtime, update(service="enabled"))
    assert record["result"] == "confirmed" and target.values(TEST)["Service"] == "Enabled"
    preview = execute.preview_undo(runtime, record["change_id"], "back", issue=True)
    assert preview["result"] == "ready"
    assert any("clients may lose access" in item for item in preview["prechecks"])
    undone = execute.undo(runtime, record["change_id"], "back", expected_plan_sha256=preview["plan_sha256"])
    assert undone["result"] == "confirmed" and target._listing() == before
    assert runtime.store.operation(undone["change_id"])["plan"]["endpoint_impact"] == TEST


# --- R06: passphrase by vault reference, enterprise authentication -----------------------------------------------------

def personal(mode="wpa3", ref=REF):
    return update(authentication="open", encryption=mode, passphrase_ref=ref)


def test_passphrase_preview_holds_the_reference_only(tmp_path):
    runtime, target = lab(tmp_path)
    preview = execute.preview(runtime, "ap", personal())
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["config", "wlan " + TEST,
                                   "open wpa3 passphrase <vault-passphrase:%s> algorithm aes" % REF, "end", "exit"]
    assert preview["predicted"]["after"]["encryption"] == "wpa3" and "passphrase-ref" not in preview["predicted"]["after"]
    assert any(REF in item and "resolves" in item for item in preview["prechecks"])
    assert SECRET not in json.dumps(preview)
    assert target.resolved == [REF]  # the reference of the plan is checked against the vault, its value is dropped


def test_passphrase_is_resolved_only_when_typed_and_stays_out_of_every_record(tmp_path):
    runtime, target = lab(tmp_path)
    record = apply_approved(runtime, personal())
    assert record["result"] == "confirmed", (steps(record), record.get("postcheck_differences"))
    assert target.last_passphrase == SECRET and target.values(TEST)["Encryption"] == "wpa3"
    assert target.values(TEST)["80211w-pmf"] == "Required"
    blob = json.dumps(runtime.store.operation(record["change_id"]), sort_keys=True) + json.dumps(record)
    blob += (tmp_path / "audit" / "audit.jsonl").read_text()
    assert SECRET not in blob and ("<vault-passphrase:%s>" % REF) in blob


def test_undo_of_a_passphrase_change_restores_the_mode_with_a_new_generated_passphrase_and_says_so(tmp_path):
    runtime, target = lab(tmp_path)
    record = apply_approved(runtime, personal())
    preview = execute.preview_undo(runtime, record["change_id"], "back")
    assert preview["result"] == "ready", preview
    assert preview["commands"][2:4] == ["open wpa2 passphrase %s algorithm aes" % ruckus.PASSPHRASE_TOKEN, "80211w-pmf 0"]
    undone = execute.undo(runtime, record["change_id"], "back")
    assert undone["result"] == "confirmed", steps(undone)
    assert ruckus.CHANGED_PASSPHRASE in json.dumps(undone) and "undo_partial" in names(undone)
    assert target.values(TEST)["Encryption"] == "wpa2" and target.values(TEST)["80211w-pmf"] == "Disabled"
    assert re.fullmatch(r"[A-Za-z0-9]{32}", target.last_passphrase) and target.last_passphrase != SECRET


def test_back_to_wpa2_resets_the_pmf_the_device_keeps_from_wpa3(tmp_path):
    """Measured on the R610: after WPA3 a later WPA2 passphrase line leaves 802.11w PMF "Required"; Admin sets it back."""
    runtime, target = lab(tmp_path)
    before = list(target.wlans[TEST])
    third = apply_approved(runtime, personal("wpa3"))
    assert third["result"] == "confirmed"
    back = apply_approved(runtime, personal("wpa2"))
    assert back["result"] == "confirmed" and target.values(TEST)["80211w-pmf"] == "Disabled"
    assert target.applied[-1][-4:] == ["open wpa2 passphrase <vault-passphrase:%s> algorithm aes" % REF, "80211w-pmf 0",
                                       "end", "exit"]


def test_a_wlan_with_its_own_pmf_setting_keeps_its_security(tmp_path):
    runtime, target = lab(tmp_path)
    target._set(target.wlans[TEST], "80211w-pmf", "Optional")
    preview = execute.preview(runtime, "ap", personal("wpa3"))
    assert preview["result"] == "rejected" and "802.11w PMF" in " ".join(preview["reasons"])


def test_a_new_passphrase_for_the_same_mode_is_a_change(tmp_path):
    runtime, target = lab(tmp_path)
    record = apply_approved(runtime, personal("wpa2"))
    assert record["result"] == "confirmed" and target.last_passphrase == SECRET
    assert target.values(TEST)["Encryption"] == "wpa2"


def test_summary_same_mode_psk_rotation_explains_why_undo_is_unavailable(tmp_path):
    runtime, target = lab(tmp_path)
    record = apply_approved(runtime, personal("wpa2"))
    assert record["result"] == "confirmed"
    for operation in (execute.preview_undo, execute.undo):
        with pytest.raises(Rejected) as error:
            operation(runtime, record["change_id"], "back")
        assert error.value.reason_codes == ["undo_not_applicable"]
        message = " ".join(error.value.reasons)
        assert "previous WLAN passphrase cannot be restored" in message and SECRET not in message
    assert len(target.applied) == 2 and target.last_passphrase == SECRET


@pytest.mark.parametrize("mode", ["undo", "compensation"])
def test_summary_recover_reports_generated_passphrase_after_interruption(tmp_path, monkeypatch, mode):
    runtime, target = lab(tmp_path)
    step = execute._step
    stop_after = "confirm_start" if mode == "undo" else "compensation_applied"

    def interrupt(*args):
        step(*args)
        if args[2] == stop_after:
            raise Interrupted()

    if mode == "undo":
        record = apply_approved(runtime, personal())
        monkeypatch.setattr(execute, "_step", interrupt)
        with pytest.raises(Interrupted):
            execute.undo(runtime, record["change_id"], "back")
    else:
        before = target._listing()
        target.check_view = lambda _listing: before
        monkeypatch.setattr(execute, "_step", interrupt)
        with pytest.raises(Interrupted):
            apply_approved(runtime, personal())
        target.check_view = None
    monkeypatch.setattr(execute, "_step", step)
    assert target.values(TEST)["Encryption"] == "wpa2" and target.last_passphrase != SECRET
    settled, = execute.recover(runtime, "ap")
    assert settled["result"] == ("confirmed" if mode == "undo" else "reverted")
    assert ruckus.CHANGED_PASSPHRASE in settled["reason"]
    assert target.last_passphrase not in json.dumps(settled)
    assert execute.recover(runtime, "ap") == []


def test_compensation_of_a_passphrase_change_says_that_the_passphrase_is_a_new_one(tmp_path):
    runtime, target = lab(tmp_path)
    before = target._listing()
    target.check_view = lambda _listing: before
    record = apply_approved(runtime, personal())
    assert record["result"] == "reverted" and ruckus.CHANGED_PASSPHRASE in record["reason"], steps(record)
    assert "compensation_partial" in names(record) and target.values(TEST)["Encryption"] == "wpa2"


@pytest.mark.parametrize("changes,why", [
    ({"authentication": "open", "encryption": "wpa3"}, "needs passphrase-ref"),
    ({"encryption": "wpa3", "passphrase-ref": REF}, "together"),
    ({"authentication": "open", "encryption": "wpa3", "passphrase-ref": "RUCKUS_ADMIN_PASS"}, "must match"),
    ({"authentication": "open", "encryption": "wpa3", "passphrase-ref": REF, "auth-server": "corp-radius"},
     "belongs to enterprise"),
    ({"authentication": "dot1x", "encryption": "wpa2"}, "auth-server in the same request"),
    ({"authentication": "dot1x", "encryption": "wpa2", "auth-server": "corp-radius", "passphrase-ref": REF},
     "no passphrase"),
    ({"authentication": "open", "encryption": "none"}, "must match"),
])
def test_incomplete_or_inconsistent_security_requests_are_refused(tmp_path, changes, why):
    runtime, target = lab(tmp_path)
    sent = len(target.sent)
    preview = execute.preview(runtime, "ap", update(**changes))
    assert preview["result"] == "rejected" and why in " ".join(preview["reasons"]), preview
    assert len(target.sent) == sent


@pytest.mark.parametrize("secret,why", [(None, "cannot be loaded"), ("short", "usable WLAN passphrase"),
                                         ("has a space in it", "usable WLAN passphrase")])
def test_an_unusable_vault_reference_is_refused_in_the_preview_with_its_code(tmp_path, secret, why):
    runtime, target = lab(tmp_path)
    target.vault.pop(REF)
    if secret is not None:
        target.vault[REF] = secret
    sent = len(target.sent)
    preview = execute.preview(runtime, "ap", personal())
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["wlan_passphrase_reference"], preview
    assert why in " ".join(preview["reasons"]) and len(target.sent) == sent
    assert secret is None or secret not in json.dumps(preview)


def test_enterprise_authentication_names_the_server_and_the_undo_returns_to_personal(tmp_path):
    runtime, target = lab(tmp_path)
    req = update(authentication="dot1x", encryption="wpa2", auth_server="corp-radius")
    preview = execute.preview(runtime, "ap", req)
    assert preview["commands"] == ["config", "wlan " + TEST, "dot1x wpa2 algorithm AES auth-server name corp-radius",
                                   "80211w-pmf 0", "end", "exit"]
    record = execute.apply(runtime, "ap", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (steps(record), record.get("postcheck_differences"))
    values = target.values(TEST)
    assert (values["Authentication"], values["Authentication Server"]) == ("802.1x-eap", "corp-radius")
    undone = execute.undo(runtime, record["change_id"], "back")
    assert undone["result"] == "confirmed", steps(undone)
    values = target.values(TEST)
    assert values["Authentication"] == "open" and values["Encryption"] == "wpa2"
    assert ruckus.CHANGED_PASSPHRASE in json.dumps(undone)


def test_back_from_enterprise_to_personal_and_the_undo_of_that_restores_enterprise(tmp_path):
    runtime, target = lab(tmp_path)
    apply_approved(runtime, update(authentication="dot1x", encryption="wpa2", auth_server="corp-radius"))
    record = apply_approved(runtime, personal("wpa2"))
    assert record["result"] == "confirmed", steps(record)
    assert target.values(TEST)["Authentication"] == "open" and target.last_passphrase == SECRET
    undone = execute.undo(runtime, record["change_id"], "back")
    assert undone["result"] == "confirmed", steps(undone)
    assert target.values(TEST)["Authentication"] == "802.1x-eap"
    assert target.applied[-1][2] == "dot1x wpa2 algorithm AES auth-server name corp-radius"


def test_an_unknown_enterprise_server_is_refused_by_the_device_and_nothing_changes(tmp_path):
    runtime, target = lab(tmp_path)
    before = list(target.wlans[TEST])
    record = apply_approved(runtime, update(authentication="dot1x", encryption="wpa2", auth_server="no-such-aaa"))
    assert record["result"] == "reverted" and target.wlans[TEST] == before


def test_security_of_another_kind_is_not_changed(tmp_path):
    runtime, target = lab(tmp_path, wlans=(TEST, RELAY, "host02"))
    # host02 is an open guest WLAN (Authentication open, Encryption none): not WPA2/WPA3
    preview = execute.preview(runtime, "ap", request(op="update", key="host02", request_id="req-g112-guest",
                                                      changes={"authentication": "open", "encryption": "wpa2",
                                                               "passphrase-ref": REF}))
    assert preview["result"] == "rejected" and "not WPA2/WPA3" in " ".join(preview["reasons"])


def test_a_stale_server_name_after_enterprise_does_not_hide_the_personal_state(tmp_path):
    runtime, target = lab(tmp_path)
    apply_approved(runtime, update(authentication="dot1x", encryption="wpa2", auth_server="corp-radius"))
    apply_approved(runtime, personal("wpa2"))
    assert target.values(TEST)["Authentication Server"] == "corp-radius"  # in an unsaved context the device keeps the name (cli_wlan.out); a defensive case
    again = execute.preview(runtime, "ap", update(max_clients=20))
    assert again["result"] == "ready", again


# --- the real access: the reference is resolved in the transport only ------------------------------------------------------

def vault_stub(monkeypatch, kind="api-token", value=SECRET):
    from netops_admin import access as access_module

    class Vault:
        def credential(self, name, where=""):
            if name != REF:
                raise KeyError(name)
            return SimpleNamespace(kind=kind, use=lambda: value)

    monkeypatch.setattr(access_module.vault, "load", lambda path, names=None: Vault())


def real_access(monkeypatch, body, secret=SECRET):
    from netops_admin.access import DeviceAccess

    command = "open wpa3 passphrase %s%s> algorithm aes" % (ruckus.PASSPHRASE_REF_PREFIX, REF)
    typed = command.replace("%s%s>" % (ruckus.PASSPHRASE_REF_PREFIX, REF), secret)
    spec = exec_ruckus.prompt_spec()
    shell = Shell([(exec_ruckus.LOGIN_PROMPT, b"Please login: "), (exec_ruckus.PASSWORD_PROMPT, b"Password: "),
                   (exec_ruckus.USER_PROMPT, b"\nruckus>"), (exec_ruckus.ENABLE_PROMPT, b"\nruckus# "),
                   (spec.anchor, ("%s\n%s\nruckus" % (typed, body)).encode()), (spec.ends[0], b"(config-wlan)# ")])
    access = DeviceAccess.__new__(DeviceAccess)
    access.credential = SimpleNamespace(login="operator", use=lambda: "dummy-login-password")
    access.device = SimpleNamespace(vault="/nonexistent/vault.json")
    monkeypatch.setattr(access, "_session", lambda: nullcontext(shell))
    return access, spec, shell, command, typed


def test_device_access_types_the_secret_and_never_stores_it(monkeypatch):
    vault_stub(monkeypatch)
    access, spec, shell, command, typed = real_access(monkeypatch, measured_ok())
    seen = []
    access.line_answered = lambda _number, answer: seen.append(answer)
    assert access.apply([command], spec) == 1
    assert shell.sent[-1] == typed and SECRET in shell.sent[-1]
    assert SECRET not in "".join(seen) and SECRET not in "".join(access.last_answers)


def test_device_access_hides_the_secret_in_a_refusal(monkeypatch):
    vault_stub(monkeypatch)
    access, spec, shell, command, typed = real_access(monkeypatch, "PSK rejected: %s" % SECRET)
    access.line_answered = lambda *_: None
    with pytest.raises(AccessError) as err:
        access.apply([command], spec)
    assert SECRET not in str(err.value) and SECRET not in "".join(access.last_answers)


def test_device_access_hides_an_ansi_split_secret_in_a_refusal(monkeypatch):
    vault_stub(monkeypatch)
    measured_refusal = next(line for line in fixture("cli_wlan_errors.out").splitlines()
                            if line.startswith("PSK Passphrase can only contain"))
    # Add a synthetic PSK echo to the measured refusal and decorate the middle of the value.
    decorated = SECRET[:8] + "\x1b[1m" + SECRET[8:16] + "\x1b[0m" + SECRET[16:]
    body = f"PSK rejected: {decorated}\n{measured_refusal}"
    access, spec, shell, command, typed = real_access(monkeypatch, body)
    with pytest.raises(AccessError) as err:
        access.apply([command], spec)

    assert shell.sent[-1] == typed
    diagnostics = {"error": str(err.value), "answer": "".join(access.last_answers)}
    leaked = [name for name, text in diagnostics.items() if SECRET in re.sub(r"\x1b\[[0-9;]*m", "", text)]
    assert not leaked
    for text in diagnostics.values():
        assert "\x1b" not in text
        assert "PSK rejected: <redacted>" in text
        assert measured_refusal in text


def test_summary_valid_vault_passphrase_can_overlap_cli_success(monkeypatch):
    # Use a valid length fictitious passphrase that also appears in the measured acceptance reply.
    secret = "successfully"
    vault_stub(monkeypatch, value=secret)
    access, spec, shell, command, typed = real_access(monkeypatch, measured_ok(), secret)
    seen = []
    access.line_answered = lambda _number, answer: seen.append(answer)
    assert access.apply([command], spec) == 1
    assert shell.sent[-1] == typed
    assert secret not in "".join(seen) and secret not in "".join(access.last_answers)


@pytest.mark.parametrize("kind,value", [("password", SECRET), ("api-token", "short")])
def test_the_transport_refuses_a_reference_that_is_not_a_usable_secret_entry(monkeypatch, kind, value):
    vault_stub(monkeypatch, kind, value)
    access, spec, shell, command, typed = real_access(monkeypatch, measured_ok())
    with pytest.raises(AccessError) as err:
        access.apply([command], spec)
    assert SECRET not in str(err.value) and shell.sent[-1:] != [typed]


def test_a_missing_vault_entry_is_refused_in_the_transport(monkeypatch):
    from netops_admin import access as access_module

    def missing(path, names=None):
        raise RuntimeError("vault file %s: names no record" % path)

    monkeypatch.setattr(access_module.vault, "load", missing)
    access, spec, shell, command, typed = real_access(monkeypatch, measured_ok())
    with pytest.raises(AccessError):
        access.apply([command], spec)


def test_the_vault_file_of_the_device_is_read_for_the_named_entry_only(tmp_path):
    from netops_admin.access import DeviceAccess

    path = tmp_path / "vault.json"
    path.write_text(json.dumps({"version": 2, "credentials": {
        REF: {"kind": "api-token", "login": None, "value": SECRET},
        "OTHER_ADMIN": {"kind": "password", "login": "admin", "value": "other-secret-value"}}}))
    path.chmod(0o600)
    access = DeviceAccess.__new__(DeviceAccess)
    access.device = SimpleNamespace(vault=str(path))
    assert access.secret_value(REF) == SECRET
    with pytest.raises(Rejected):
        access.secret_value("OTHER_ADMIN")  # a login credential is not a passphrase reference
    with pytest.raises(Rejected):
        access.secret_value("MISSING_ENTRY")


def measured_ok():
    return "The command was executed successfully. To save the changes, type 'end' or 'exit'."


# --- R23: DHCP relay server entries ---------------------------------------------------------------------------------------

def test_relay_entry_create_update_delete_with_readback_and_undo(tmp_path):
    runtime, target = lab(tmp_path)
    req = relay_request("create", first="192.0.2.10", second="192.0.2.11", description="lab-relay")
    preview = execute.preview(runtime, "ap", req)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["config", "dhcp " + RELAY, "first 192.0.2.10", "second 192.0.2.11",
                                   "description lab-relay", "end", "exit"]
    assert preview["predicted"]["after"] == {"first": "192.0.2.10", "second": "192.0.2.11", "description": "lab-relay"}
    assert target.relays == {}
    created_record = execute.apply(runtime, "ap", req, expected_plan_sha256=preview["plan_sha256"])
    assert created_record["result"] == "confirmed", (steps(created_record), created_record.get("postcheck_differences"))
    assert target.relays[RELAY] == {"description": "lab-relay", "addresses": ["192.0.2.10", "192.0.2.11"]}
    changed = apply_approved(runtime, relay_request("update", second=None, first="192.0.2.12"))
    assert changed["result"] == "confirmed", steps(changed)
    assert target.relays[RELAY]["addresses"] == ["192.0.2.12", ""]
    assert target.applied[-1] == ["config", "no dhcp " + RELAY, "dhcp " + RELAY, "first 192.0.2.12",
                                  "description lab-relay", "end", "exit"]  # the firmware cannot save a change in place
    undone = execute.undo(runtime, changed["change_id"], "back")
    assert undone["result"] == "confirmed" and target.relays[RELAY]["addresses"] == ["192.0.2.10", "192.0.2.11"]
    deleted = apply_approved(runtime, relay_request("delete"))
    assert deleted["result"] == "confirmed" and target.relays == {}
    assert target.applied[-1] == ["config", "no dhcp " + RELAY, "exit"]
    restored = execute.undo(runtime, deleted["change_id"], "back")
    assert restored["result"] == "confirmed", steps(restored)
    assert target.relays[RELAY] == {"description": "lab-relay", "addresses": ["192.0.2.10", "192.0.2.11"]}
    removed = execute.undo(runtime, created_record["change_id"], "remove")
    assert removed["result"] == "confirmed" and target.relays == {}


def test_the_firmware_refuses_to_save_a_change_in_place_which_is_why_an_entry_is_retyped():
    import fake_ruckus
    assert "'is-partial' API body invalid" in fixture("cli_dhcp_update.out")
    target = FakeRuckus()
    target.relays["x"] = {"description": "", "addresses": ["192.0.2.1", ""]}
    spec = exec_ruckus.prompt_spec()
    with pytest.raises(AccessError):
        target.apply(["config", "dhcp x", "second 192.0.2.2", "end"], spec)
    assert target.relays["x"]["addresses"] == ["192.0.2.1", ""]


def test_a_description_is_cleared_with_an_empty_string_and_restored_by_the_undo(tmp_path):
    runtime, target = lab(tmp_path)
    apply_approved(runtime, relay_request("create", first="192.0.2.10", description="lab-relay"))
    cleared = apply_approved(runtime, relay_request("update", description=None))
    assert cleared["result"] == "confirmed" and "description" not in " ".join(target.applied[-1])
    execute.undo(runtime, cleared["change_id"], "back")
    assert target.relays[RELAY]["description"] == "lab-relay"


def test_relay_requests_without_the_hash_or_selection_or_valid_values_are_refused(tmp_path):
    runtime, target = lab(tmp_path)
    for changes, why in (({"first": "999.1.1.1"}, "IPv4"), ({"first": "192.0.2.1", "second": "192.0.2.1"}, "must differ"),
                         ({"second": "192.0.2.2"}, "first")):
        preview = execute.preview(runtime, "ap", relay_request("create", **changes))
        assert preview["result"] == "rejected" and why in " ".join(preview["reasons"]), (changes, preview)
    other = execute.preview(runtime, "ap", relay_request("create", key="other-relay", first="192.0.2.1"))
    assert other["reason_codes"] == ["wlan_not_selected"]
    assert not target.relays


def test_a_relay_entry_is_not_changed_while_a_wlan_has_the_relay_enabled(tmp_path):
    runtime, target = lab(tmp_path)
    apply_approved(runtime, relay_request("create", first="192.0.2.10"))
    target._set(target.wlans[TEST], "DHCP relay", "Enabled")
    for req in (relay_request("update", first="192.0.2.30"), relay_request("delete")):
        preview = execute.preview(runtime, "ap", req)
        assert preview["result"] == "rejected" and "use a DHCP relay" in " ".join(preview["reasons"])
    assert target.relays[RELAY]["addresses"][0] == "192.0.2.10"


def test_an_unreadable_relay_listing_is_not_taken_for_an_empty_one(tmp_path):
    runtime, target = lab(tmp_path)
    target.dhcp_unreadable = True
    try:
        refused = execute.preview(runtime, "ap", relay_request("create", first="192.0.2.10"))
    except Rejected:
        refused = {"result": "rejected"}
    assert refused["result"] == "rejected"
    target.dhcp_unreadable = False
    preview = execute.preview(runtime, "ap", relay_request("create", first="192.0.2.10"))
    assert preview["result"] == "ready"  # nothing configured is a legitimate empty listing


def test_a_relay_listing_that_the_check_account_cannot_read_confirms_nothing(tmp_path):
    runtime, target = lab(tmp_path)
    req = relay_request("create", first="192.0.2.10")
    preview = execute.preview(runtime, "ap", req)
    target.check_view = lambda text: (
        "show dhcp all\nSomething unexpected\nruckus# " if "DHCP servers" in text and len(target.applied) > 1 else text)
    record = execute.apply(runtime, "ap", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] != "confirmed"


def test_a_failed_relay_write_is_returned(tmp_path):
    runtime, target = lab(tmp_path)
    target.refuse["first 192.0.2.10"] = "The IP address is invalid. Please set the IP address, and then try again."
    record = apply_approved(runtime, relay_request("create", first="192.0.2.10"))
    assert record["result"] == "reverted" and target.relays == {}


def test_the_profiles_of_g112_are_measured_and_exact():
    profile = find_profile("ruckus", "dhcp-relay", "200.15.6.212 build 27")
    assert profile.measured and profile.exact_versions and profile.table_scoped_key
    wlan_profile = find_profile("ruckus", "wlan", "200.15.6.212 build 27")
    for name in ("max-clients", "isolation-ap", "l2acl", "l3acl", "rate-perssid-uplink", "rate-perssid-downlink",
                 "rate-uplink", "rate-downlink", "authentication", "encryption", "auth-server", "passphrase-ref"):
        assert name in wlan_profile.attributes and wlan_profile.attributes[name].update
    assert "WLAN_PSK_" in wlan_profile.attributes["passphrase-ref"].pattern.pattern


def test_a_newer_firmware_is_a_warning_not_a_block(tmp_path):
    """G00-1: a build outside the tested one only adds firmware_support untested; it never blocks the change."""
    target = FakeRuckus()
    original = target.query
    target.query = lambda command: original(command).replace("200.15.6.212 build 27", "200.15.6.212 build 99")
    runtime = make_runtime(tmp_path, target, certified=False, wlans=(TEST, RELAY))
    from enrollment_helpers import certify
    certify(runtime, target, "ap")
    assert apply_approved(runtime, request())["result"] == "confirmed"
    preview = execute.preview(runtime, "ap", update(max_clients=37))
    assert preview["result"] == "ready" and preview["firmware_support"]["status"] == "untested", preview
    assert "200.15.6.212 build 99" in preview["firmware_support"]["message"]
