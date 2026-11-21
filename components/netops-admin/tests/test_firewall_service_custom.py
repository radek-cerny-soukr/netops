from __future__ import annotations

import json
from dataclasses import replace
from importlib import resources

import pytest
from fake_fortios import FakeFortiOS as FakeFortiOS800
from fake_webhook import FakeFortiOSWebhook
from test_execute import make_runtime, request

from netops_admin import config, engine, execute, fortios, profiles
from netops_admin.config import _device
from netops_admin.errors import Rejected

TABLE = "firewall service custom"


class FakeFortiOS(FakeFortiOS800):
    firmware = ("7.6.8", "3744")


def service(**fields):
    fields.setdefault("table", TABLE)
    fields.setdefault("key", "TCP-8443")
    fields.setdefault("op", "create")
    fields.setdefault("changes", {"tcp-portrange": "8443"})
    return request(**fields)


def runtime(tmp_path, device, **fields):
    fields.setdefault("opt_in", (TABLE,))
    return make_runtime(tmp_path, device, **fields)


def rejected(tmp_path, device, req, **fields):
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime(tmp_path, device, **fields), "lab", req)
    return " ".join(caught.value.reasons)


def test_profile_is_measured_exact_and_opt_in():
    for firmware in ("7.6.8 build3744", "8.0.2 build0251"):
        profile = profiles.find_profile("fortios", TABLE, firmware)
        assert not profile.provisional and profile.exact_versions
        assert profile.ops == ("create", "update", "delete")
        assert profile.measured is True
        assert profile.versions == ("7.6.8 build3744", "8.0.2 build0251")
        assert profile.fixed == {
            "protocol": "TCP/UDP/UDP-Lite/SCTP", "category": "", "helper": "auto",
            "check-reset-range": "default", "color": "0", "fabric-object": "disable",
            "iprange": "0.0.0.0", "fqdn": "", "udplite-portrange": "", "sctp-portrange": "",
            "tcp-halfclose-timer": "0", "tcp-halfopen-timer": "0", "tcp-timewait-timer": "0",
            "tcp-rst-timer": "0", "udp-idle-timer": "0", "session-ttl": "0",
        }
        assert profile.volatile == ("uuid",)
        assert profile.inverse_identity_changes == {"delete": ("uuid",)}
        assert set(profile.attributes) == {"tcp-portrange", "udp-portrange", "comment"}
        assert all(profile.attributes[name].default is None for name in ("tcp-portrange", "udp-portrange"))
        assert profile.attributes["comment"].default == ""
        assert profile.attributes["comment"].unset
        assert not profile.attributes["tcp-portrange"].referenced_update
        assert not profile.attributes["udp-portrange"].referenced_update
        assert profile.attributes["comment"].referenced_update
        assert profile.rollback_evidence.startswith("Measured directly on devices:")
        assert "referenced-delete refusal (-23)" in profile.rollback_evidence
        assert "Not measured: the safeguard firing a POST inverse" in profile.rollback_evidence
    for name in ("ALL", "HTTP", "HTTPS", "SSH", "DNS", "PING", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "webproxy"):
        assert name in profile.protected_keys
    # G00-1: other builds are untested, not refused
    for other in ("7.6.7 build3704", "7.6.9 build3800", "8.0.0 build0167", "8.0.1 build0185"):
        assert profiles.firmware_support(profiles.find_profile("fortios", TABLE, other), other)["status"] == "untested"
    assert TABLE in config.OPT_IN_TABLES


@pytest.mark.parametrize("firmware", ["7.6.8 build3744", "8.0.2 build0251"])
def test_measured_defaults_normalize_like_abbreviated_show(firmware):
    profile = profiles.find_profile("fortios", TABLE, firmware)
    abbreviated = {"uuid": "new-uuid", "tcp-portrange": "8443"}
    full = dict(abbreviated, **profile.fixed, comment="")
    assert engine.normalize(profile, full) == engine.normalize(profile, abbreviated) == ({"tcp-portrange": "8443"}, [])
    assert engine.normalize(profile, dict(full, comment="x"))[0]["comment"] == "x"
    assert engine.normalize(profile, dict(full, helper="ftp"))[1] == ["helper ftp"]
    assert engine.normalize(profile, dict(full, protocol="ICMP"))[1] == ["protocol ICMP"]
    assert not {"visibility", "proxy", "app-service-type"} & set(profile.fixed)


def test_opt_in_off_by_default(tmp_path):
    device = FakeFortiOS()
    assert "not enabled" in rejected(tmp_path, device, service(), opt_in=())
    assert "TCP-8443" not in device.services


def test_opt_in_config_accepts_the_service_table_on_fortios_only():
    data = {"platform": "fortios", "address": "192.0.2.1", "port": 22,
            "host_key_fingerprint": "SHA256:" + "A" * 43, "vault": "/x", "credential": "rw",
            "check_credential": "ro", "opt_in": [TABLE]}
    assert _device("lab", dict(data)).opt_in == (TABLE,)
    with pytest.raises(Rejected) as caught:
        _device("lab", dict(data, platform="exos", firmware="33.7.1.6", accounts=["admin"]))
    assert "firewall service custom is a FortiOS table" in " ".join(caught.value.reasons)


def test_create_update_undo_and_delete_with_undo(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    record = execute.apply(rt, "lab", service())
    assert record["result"] == "confirmed"
    assert device.services["TCP-8443"]["tcp-portrange"] == "8443"
    assert "protocol" not in device.services["TCP-8443"]
    assert not device.stitches and not device.triggers and not device.actions
    record = execute.apply(rt, "lab", service(op="update", changes={"comment": "web admin", "udp-portrange": "8443"},
                                              request_id="req-svc-update-1"))
    assert record["result"] == "confirmed"
    assert device.services["TCP-8443"]["comment"] == "web admin"
    assert device.services["TCP-8443"]["udp-portrange"] == "8443"
    back = execute.undo(rt, record["change_id"], "investigated")
    assert back["result"] == "confirmed"
    assert "comment" not in device.services["TCP-8443"] and "udp-portrange" not in device.services["TCP-8443"]
    uuid = device.services["TCP-8443"]["uuid"]
    record = execute.apply(rt, "lab", service(op="delete", changes={}, request_id="req-svc-delete-1"))
    assert record["result"] == "confirmed" and "TCP-8443" not in device.services
    back = execute.undo(rt, record["change_id"], "investigated")
    assert back["result"] == "confirmed"
    assert device.services["TCP-8443"]["tcp-portrange"] == "8443"
    assert device.services["TCP-8443"]["uuid"] != uuid
    assert not device.stitches and not device.triggers and not device.actions


def test_undo_of_create_deletes_the_service(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device)
    record = execute.apply(rt, "lab", service(changes={"tcp-portrange": "8000-8080", "comment": "range"}))
    assert record["result"] == "confirmed" and device.services["TCP-8443"]["tcp-portrange"] == "8000-8080"
    back = execute.undo(rt, record["change_id"], "investigated")
    assert back["result"] == "confirmed" and "TCP-8443" not in device.services


def test_create_rendering_is_quoted_and_sorted():
    profile = profiles.find_profile("fortios", TABLE, "7.6.8 build3744")
    assert fortios.render_create(profile, "TCP-8443", {"tcp-portrange": "8443", "comment": "x"}) == [
        "config firewall service custom", '    edit "TCP-8443"', '        set comment "x"',
        '        set tcp-portrange "8443"', "    next", "end"]
    assert fortios.render_delete(profile, "TCP-8443") == [
        "config firewall service custom", '    delete "TCP-8443"', "end"]


def test_delete_of_a_referenced_service_is_refused(tmp_path):
    device = FakeFortiOS()
    device.services["SRV-USED"] = {"uuid": device._uuid(), "tcp-portrange": "8443"}
    device.policies["1"]["service"] = "SRV-USED"
    reasons = rejected(tmp_path, device, service(key="SRV-USED", op="delete", changes={}))
    assert "is referenced in the configuration" in reasons
    assert "SRV-USED" in device.services and not device.applied_blocks


def test_referenced_service_keeps_its_ports_but_may_change_the_comment(tmp_path):
    device = FakeFortiOS()
    device.services["SRV-USED"] = {"uuid": device._uuid(), "tcp-portrange": "8443"}
    device.policies["1"]["service"] = "SRV-USED"
    rt = runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(rt, "lab", service(key="SRV-USED", op="update", changes={"tcp-portrange": "9443"}))
    assert "cannot change on a referenced object" in " ".join(caught.value.reasons)
    assert device.services["SRV-USED"]["tcp-portrange"] == "8443"
    record = execute.apply(rt, "lab", service(key="SRV-USED", op="update", changes={"comment": "used"},
                                              request_id="req-svc-comment-1"))
    assert record["result"] == "confirmed" and device.services["SRV-USED"]["comment"] == "used"


@pytest.mark.parametrize("key,op,changes", [
    ("HTTP", "delete", {}),
    ("HTTPS", "update", {"comment": "x"}),
    ("http", "update", {"comment": "x"}),
    ("ALL", "create", {"tcp-portrange": "1-65535"}),
    ("SSH", "create", {"tcp-portrange": "22"}),
    ("PING", "create", {"tcp-portrange": "7"}),
    ("ALL_TCP", "create", {"tcp-portrange": "1-65535"}),
])
def test_predefined_services_are_protected(tmp_path, key, op, changes):
    device = FakeFortiOS()
    before = {name: dict(values) for name, values in device.services.items()}
    assert "is protected" in rejected(tmp_path, device, service(key=key, op=op, changes=changes))
    assert device.services == before and not device.applied_blocks


def test_configured_protection_also_applies(tmp_path):
    device = FakeFortiOS()
    device.services["LOCAL-MGMT"] = {"uuid": device._uuid(), "tcp-portrange": "10443"}
    reasons = rejected(tmp_path, device, service(key="LOCAL-MGMT", op="delete", changes={}),
                       protected={TABLE: ["LOCAL-MGMT"]})
    assert "is protected" in reasons and "LOCAL-MGMT" in device.services


@pytest.mark.parametrize("changes,fragment", [
    ({"tcp-portrange": "0"}, "is not one port range"),
    ({"tcp-portrange": "70000"}, "is not one port range"),
    ({"tcp-portrange": "9000-8000"}, "is not one port range"),
    ({"udp-portrange": "53:0"}, "is not one port range"),
    ({"tcp-portrange": "80 443"}, "must match"),
    ({"tcp-portrange": "80,443"}, "must match"),
    ({"comment": "no ports"}, "needs tcp-portrange or udp-portrange"),
    ({"tcp-portrange": "8443", "protocol": "ICMP"}, "attribute protocol is not in the profile"),
])
def test_invalid_port_ranges_are_refused(tmp_path, changes, fragment):
    device = FakeFortiOS()
    assert fragment in rejected(tmp_path, device, service(changes=changes))
    assert "TCP-8443" not in device.services


def test_removing_the_last_port_range_is_refused(tmp_path):
    device = FakeFortiOS()
    device.services["TCP-8443"] = {"uuid": device._uuid(), "tcp-portrange": "8443"}
    reasons = rejected(tmp_path, device, service(op="update", changes={"tcp-portrange": None}))
    assert "needs tcp-portrange or udp-portrange" in reasons
    assert device.services["TCP-8443"]["tcp-portrange"] == "8443"


def test_existing_service_outside_the_profile_is_refused(tmp_path):
    device = FakeFortiOS()
    device.services["ICMP-X"] = {"uuid": device._uuid(), "protocol": "ICMP"}
    device.services["MULTI"] = {"uuid": device._uuid(), "tcp-portrange": "80 443"}
    device.services["CAT"] = {"uuid": device._uuid(), "category": "Web Access", "tcp-portrange": "81"}
    assert "outside the profile: protocol ICMP" in rejected(
        tmp_path, device, service(key="ICMP-X", op="update", changes={"comment": "x"}))
    assert "is not one port range" in rejected(
        tmp_path, device, service(key="MULTI", op="delete", changes={}, request_id="req-svc-multi-1"))
    assert "outside the profile: category" in rejected(
        tmp_path, device, service(key="CAT", op="delete", changes={}, request_id="req-svc-cat-1"))
    assert {"ICMP-X", "MULTI", "CAT"} <= set(device.services)


def test_create_of_a_name_in_use_is_refused(tmp_path):
    device = FakeFortiOS()
    reasons = rejected(tmp_path, device, service(key="srv-web"))
    assert "srv-web" not in device.services and reasons


def test_firing_reverts_a_create_on_the_cli_script_firmware(tmp_path):
    device = FakeFortiOS()
    device.on_apply = lambda fake, block: setattr(
        fake, "check_unreadable", fake.check_unreadable or block[0] == "config " + TABLE)
    record = execute.apply(runtime(tmp_path, device), "lab", service())
    assert record["result"] == "reverted" and "TCP-8443" not in device.services


def test_all_shipped_profiles_are_measured():
    loaded = profiles.load_profiles()
    assert all(profile.measured for profile in loaded.values())


def _service_profile_data():
    path = resources.files("netops_admin") / "profiles" / "fortios-firewall-service-custom.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(("mutate", "fragment"), [
    (lambda data: data.update(measured="no"), "measured must be true or false"),
    (lambda data: data.update(provisional=False), "must be provisional with exact_versions"),
    (lambda data: data.update(exact_versions=False), "must be provisional with exact_versions"),
])
def test_unmeasured_profile_fields_are_checked(mutate, fragment):
    data = _service_profile_data()
    data.update(measured=False, provisional=True)
    mutate(data)
    with pytest.raises(profiles.ProfileError) as caught:
        profiles.parse_profile(data)
    assert fragment in str(caught.value)


def test_a_profile_without_the_field_is_measured():
    data = _service_profile_data()
    data.pop("measured")
    assert profiles.parse_profile(data).measured is True


def test_simulation_switch_must_be_a_boolean(tmp_path):
    with pytest.raises(ValueError):
        execute.Runtime(None, None, simulate_unmeasured_profiles="yes")


def test_only_the_runtime_knows_the_simulation_switch():
    package = resources.files("netops_admin")
    for entry in package.iterdir():
        if entry.name.endswith(".py") and entry.name != "execute.py":
            assert "simulate_unmeasured_profiles" not in entry.read_text(encoding="utf-8"), entry.name


def _untouchable(_device):
    raise AssertionError("the device must not be contacted for an unmeasured profile")


@pytest.mark.parametrize("firmware", [("7.6.8", "3744"), ("8.0.2", "0251")])
@pytest.mark.parametrize("op,key,changes", [
    ("create", "TCP-8443", {"tcp-portrange": "8443"}),
    ("update", "SRV-A", {"comment": "x"}),
    ("delete", "SRV-A", {}),
])
def test_production_runtime_refuses_an_unmeasured_profile_before_any_device_access(tmp_path, monkeypatch, firmware, op, key, changes):
    loaded = profiles.load_profiles()
    loaded[("fortios", TABLE)] = replace(loaded[("fortios", TABLE)], measured=False, provisional=True)
    monkeypatch.setattr(execute, "load_profiles", lambda: loaded)
    device = FakeFortiOS()
    device.firmware = firmware
    device.services["SRV-A"] = {"uuid": device._uuid(), "tcp-portrange": "8443"}
    before = device.snapshot()
    services = {name: dict(values) for name, values in device.services.items()}
    rt = runtime(tmp_path, device, simulate_unmeasured_profiles=False)
    assert rt.config.devices["lab"].opt_in == (TABLE,)
    rt.access_factory = _untouchable
    req = service(key=key, op=op, changes=changes)
    for call in (execute.preview, execute.apply):
        with pytest.raises(Rejected) as caught:
            call(rt, "lab", req)
        assert caught.value.reason_codes == ["profile_not_measured"]
        assert "not measured on a device" in " ".join(caught.value.reasons)
    assert device.services == services and not device.applied_blocks
    assert not device.stitches and not device.triggers and not device.actions
    assert device.snapshot() == before
    assert rt.store.records() == []


def test_production_runtime_still_runs_the_measured_address_profile(tmp_path):
    device = FakeFortiOS()
    rt = runtime(tmp_path, device, simulate_unmeasured_profiles=False)
    record = execute.apply(rt, "lab", request())
    assert record["result"] == "confirmed" and "new-host" in device.addresses


@pytest.mark.parametrize("firmware", [("7.6.8", "3744"), ("8.0.2", "0251")])
def test_production_preview_accepts_the_measured_service_profile(tmp_path, firmware):
    device = FakeFortiOS() if firmware[0] == "7.6.8" else FakeFortiOSWebhook()
    device.firmware = firmware
    result = execute.preview(runtime(tmp_path, device), "lab", service())
    assert result["result"] == "ready"
    assert not any("NOT MEASURED" in check for check in result["prechecks"])
    assert f"firmware {firmware[0]} build{firmware[1]} is measured for this profile" in result["prechecks"]
    assert not device.applied_blocks and "TCP-8443" not in device.services
