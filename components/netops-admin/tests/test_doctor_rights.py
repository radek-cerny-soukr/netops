from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest
from fake_exos import FakeExos
from fake_fortiadc import FakeFortiADC
from fake_fortios import FakeFortiOS
from fake_webhook import FakeFortiOSWebhook
from test_execute import make_runtime
from test_execute_exos import make_runtime as make_exos_runtime

from netops_admin import access, cli, enrollment, readiness
from netops_admin import config as config_module
from netops_admin.access import AccessError
from netops_admin.config import Notify
from netops_admin.errors import Rejected

WRITE = "write account rights"
CHECK = "check account rights"
TABLE = "Accounts and least privilege"
NO_ADAPTER = "platform 'fortiadc' has no plan and apply adapter"


class Fake768(FakeFortiOS):
    firmware = ("7.6.8", "3744")


def checks(report):
    return {item["check"]: item for item in report["checks"]}


def doctor(tmp_path, device):
    return readiness.doctor(make_runtime(tmp_path, device), "lab")


def adc_runtime(tmp_path, device):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    lab = dataclasses.replace(runtime.config.devices["lab"], platform="fortiadc")
    runtime.config = dataclasses.replace(runtime.config, devices={"lab": lab})
    runtime.access_factory = lambda _device: device
    return runtime


def adc_doctor(tmp_path, device):
    with pytest.raises(Rejected) as refused:
        readiness.doctor(adc_runtime(tmp_path, device), "lab")
    reasons = refused.value.reasons
    assert reasons[0] == NO_ADAPTER
    return {line.split(": ", 1)[0]: line.split(": ", 1)[1] for line in reasons[1:]}


def adc_rights(line):
    for status in (readiness.OK, readiness.WARNING, readiness.UNVERIFIED, readiness.SKIPPED):
        if line == status or line.startswith(status + " ("):
            return status, line[len(status) + 2:-1]
    raise AssertionError(line)


def enrolled(tmp_path, device):
    runtime = make_runtime(tmp_path, device)
    runtime.require_export = False
    runtime.config = dataclasses.replace(runtime.config, export_status_file=None, notify=Notify(
        "https://notify.example.invalid", str(tmp_path / "topic"), 10.0, True))
    runtime.notifier = lambda _record: "sent"
    assert enrollment.run(runtime, "lab", "192.0.2.254/32")["enrollment"] == "valid"
    return runtime


def rights(item):
    return item["status"], item["detail"]


def test_super_admin_write_account_on_768_is_a_warning(tmp_path):
    device = Fake768()
    device.account_profiles["netops-rw"] = "super_admin"
    status, detail = rights(checks(doctor(tmp_path, device))[WRITE])
    assert status == readiness.WARNING
    assert "super_admin" in detail and TABLE in detail
    assert "Admin write, firewall policy (FortiOS 7.6.8, cli-script safeguard)" in detail


def test_prof_admin_write_account_on_768_is_a_warning(tmp_path):
    device = Fake768()
    device.account_profiles["netops-rw"] = "prof_admin"
    status, detail = rights(checks(doctor(tmp_path, device))[WRITE])
    assert status == readiness.WARNING and "prof_admin" in detail


def test_own_write_profile_on_768_is_ok(tmp_path):
    device = Fake768()
    status, detail = rights(checks(doctor(tmp_path, device))[WRITE])
    assert status == readiness.OK and "netops-write" in detail


def test_super_admin_write_account_on_802_is_ok(tmp_path):
    device = FakeFortiOSWebhook()
    device.account_profiles["netops-rw"] = "super_admin"
    status, detail = rights(checks(doctor(tmp_path, device))[WRITE])
    assert status == readiness.OK and "webhook safeguard" in detail


def test_other_write_profile_on_802_leaves_the_verdict_to_the_webhook_check(tmp_path):
    device = FakeFortiOSWebhook()
    device.account_profiles["netops-rw"] = "prof_admin"
    assert checks(doctor(tmp_path, device))[WRITE]["status"] == readiness.OK


def test_unknown_firmware_with_super_admin_cannot_be_verified(tmp_path, monkeypatch):
    device = Fake768()
    device.account_profiles["netops-rw"] = "super_admin"
    def unreadable(text, firmware):
        raise ValueError("no header")

    monkeypatch.setattr(readiness.engine, "adapter_for", lambda _platform: SimpleNamespace(load=unreadable))
    status, detail = rights(checks(doctor(tmp_path, device))[WRITE])
    assert status == readiness.UNVERIFIED and "firmware" in detail


def test_read_only_check_account_is_ok(tmp_path):
    device = FakeFortiOS()
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.OK and "netops-check" in detail


@pytest.mark.parametrize("group", ["fwgrp", "sysgrp", "wifi"])
def test_read_write_group_on_the_check_account_is_a_warning(tmp_path, group):
    device = FakeFortiOS()
    device.profile_rights["netops-check"][group] = "read-write"
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.WARNING
    assert "%s read-write" % group in detail and "Admin check" in detail and TABLE in detail


def test_cli_config_on_the_check_account_is_a_warning(tmp_path):
    device = FakeFortiOS()
    device.profile_rights["netops-check"]["cli-config"] = "enable"
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.WARNING and "cli-config enable" in detail


@pytest.mark.parametrize("profile", ["super_admin", "prof_admin"])
def test_administrator_profile_on_the_check_account_is_a_warning(tmp_path, profile):
    device = FakeFortiOS()
    device.account_profiles["netops-check"] = profile
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.WARNING and profile in detail and "Admin check" in detail
    assert not any("accprofile" in command for _login, command in device.rights_queries)


def test_custom_group_cannot_be_verified(tmp_path):
    device = FakeFortiOS()
    device.profile_rights["netops-check"]["fwgrp"] = "custom"
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.UNVERIFIED and "fwgrp custom" in detail


def test_custom_group_next_to_a_read_write_group_is_still_a_warning(tmp_path):
    device = FakeFortiOS()
    device.profile_rights["netops-check"].update(fwgrp="custom", netgrp="read-write")
    assert checks(doctor(tmp_path, device))[CHECK]["status"] == readiness.WARNING


def test_invisible_profile_cannot_be_verified(tmp_path):
    device = FakeFortiOS()
    del device.profile_rights["netops-check"]
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.UNVERIFIED and "netops-check" in detail


def test_each_account_reads_only_its_own_entry(tmp_path):
    device = FakeFortiOS()
    doctor(tmp_path, device)
    assert device.rights_queries == [
        ("netops-rw", 'show system admin "netops-rw"'),
        ("netops-check", 'show system admin "netops-check"'),
        ("netops-check", 'show system accprofile "netops-check"'),
    ]


def test_missing_admin_entry_cannot_be_verified_with_the_device_answer(tmp_path):
    device = FakeFortiOS()
    del device.account_profiles["netops-check"]
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.UNVERIFIED and "entry is not found in table" in detail
    assert "RADIUS" in detail and "cli-show" not in detail


def test_refused_admin_entry_names_cli_show_and_not_a_remote_login(tmp_path):
    device = FakeFortiOS()
    device.rights_answers['show system admin "netops-check"'] = "Unknown action 0\n"
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.UNVERIFIED and "Unknown action 0" in detail
    assert "does not have cli-show" in detail and "RADIUS" not in detail


def test_refusal_on_a_line_with_a_secret_is_reported_without_the_line(tmp_path):
    device = FakeFortiOS()
    device.rights_answers['show system accprofile "netops-check"'] = (
        "Command fail. Return code -61 (api-key s3cr3tVALUE)\n")
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.UNVERIFIED and "Command fail" in detail and "withheld" in detail
    assert "s3cr3tVALUE" not in detail and "api-key" not in detail


def test_admin_entry_without_a_profile_cannot_be_verified(tmp_path):
    device = FakeFortiOS()
    device.rights_answers['show system admin "netops-rw"'] = (
        'config system admin\n    edit "netops-rw"\n        set remote-auth enable\n        set wildcard enable\n'
        '        set remote-group "ops"\n    next\nend\n')
    status, detail = rights(checks(doctor(tmp_path, device))[WRITE])
    assert status == readiness.UNVERIFIED and "no local access profile" in detail


@pytest.mark.parametrize("answer,shown", [
    ("Unknown action 0\n", "Unknown action 0"),
    ("command parse error before 'accprofile'\nCommand fail. Return code -61\n",
     "command parse error before 'accprofile' | Command fail. Return code -61"),
])
def test_refused_read_cannot_be_verified_with_the_exact_message(tmp_path, answer, shown):
    device = FakeFortiOS()
    device.rights_answers['show system accprofile "netops-check"'] = answer
    status, detail = rights(checks(doctor(tmp_path, device))[CHECK])
    assert status == readiness.UNVERIFIED and shown in detail


def test_failed_read_cannot_be_verified_and_the_doctor_goes_on(tmp_path, monkeypatch):
    device = FakeFortiOS()

    def failing(command, check=False):
        raise AccessError("query failed: connection reset")

    monkeypatch.setattr(device, "own_query", failing)
    report = doctor(tmp_path, device)
    found = checks(report)
    assert rights(found[WRITE]) == (readiness.UNVERIFIED, "the rights cannot be read: query failed: connection reset")
    assert found[CHECK]["status"] == readiness.UNVERIFIED
    assert found["enrollment"]["status"] == readiness.OK


def test_secrets_never_reach_the_report(tmp_path):
    device = Fake768()
    device.account_profiles["netops-rw"] = "super_admin"
    device.rights_answers['show system admin "netops-check"'] = (
        'config system admin\n    edit "netops-check"\n        set password ENC SH2c2VjcmV0\n'
        '-----BEGIN CERTIFICATE-----\nMIIBfake\nUnknown action 0\n    next\nend\n')
    report = doctor(tmp_path, device)
    text = repr(report)
    assert "ENC" not in text and "SH2c2VjcmV0" not in text and "BEGIN" not in text and "MIIBfake" not in text
    assert "Unknown action 0" in checks(report)[CHECK]["detail"]


def test_warnings_keep_the_device_ready_and_the_exit_code(tmp_path, monkeypatch, capsys):
    device = Fake768()
    device.account_profiles.update({"netops-rw": "super_admin", "netops-check": "super_admin"})
    runtime = enrolled(tmp_path, device)
    report = readiness.doctor(runtime, "lab")
    assert checks(report)[WRITE]["status"] == readiness.WARNING
    assert checks(report)[CHECK]["status"] == readiness.WARNING
    assert report["ready"] is True
    monkeypatch.setattr(config_module, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "build_runtime", lambda *_args, **_kwargs: runtime)
    assert cli.main(["doctor", "--config", str(tmp_path / "admin.json"), "--device", "lab"], require_export=False) == 0
    assert '"warning"' in capsys.readouterr().out


def test_unverified_rights_keep_the_device_ready(tmp_path):
    device = Fake768()
    device.rights_unreadable = True
    runtime = enrolled(tmp_path, device)
    report = readiness.doctor(runtime, "lab")
    assert checks(report)[CHECK]["status"] == readiness.UNVERIFIED
    assert report["ready"] is True


def test_unreachable_device_skips_the_rights(tmp_path):
    device = FakeFortiOS()
    device.unreadable = True
    found = checks(doctor(tmp_path, device))
    assert found[WRITE]["status"] == readiness.SKIPPED and found[CHECK]["status"] == readiness.SKIPPED


def test_exos_has_no_rights_check(tmp_path):
    found = checks(readiness.doctor(make_exos_runtime(tmp_path, FakeExos()), "sw"))
    assert WRITE not in found and CHECK not in found


def test_adc_doctor_still_refuses_as_before(tmp_path):
    device = FakeFortiADC()
    device.unreadable = True
    found = adc_doctor(tmp_path, device)
    assert adc_rights(found[WRITE])[0] == readiness.UNVERIFIED
    assert adc_rights(found[CHECK])[0] == readiness.UNVERIFIED


def test_adc_doctor_refuses_on_the_command_line_and_in_mcp(tmp_path, monkeypatch, capsys):
    from test_mcp_server import call

    from netops_admin import mcp_server

    runtime = adc_runtime(tmp_path, FakeFortiADC())
    monkeypatch.setattr(config_module, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "build_runtime", lambda *_args, **_kwargs: runtime)
    assert cli.main(["doctor", "--config", str(tmp_path / "admin.json"), "--device", "lab"],
                    require_export=False) == cli.EXIT_REJECTED
    assert '"ready"' not in capsys.readouterr().out
    monkeypatch.setattr(mcp_server, "_CONFIGURATION", runtime.config)
    monkeypatch.setattr(mcp_server, "build_runtime", lambda *_args, **_kwargs: runtime)
    answer = call("admin_doctor", {"device": "lab"})
    assert answer["result"] == "rejected" and answer["reasons"][0] == NO_ADAPTER and "ready" not in answer


def test_adc_system_admin_write_account_is_ok(tmp_path):
    found = adc_doctor(tmp_path, FakeFortiADC())
    status, detail = adc_rights(found[WRITE])
    assert status == readiness.OK and "system administrator" in detail and "pool-member" in detail
    assert found["credentials"] == readiness.OK


def test_adc_write_account_without_system_admin_is_ok(tmp_path):
    device = FakeFortiADC()
    device.admins["netops-rw"] = {"access-profile": "netops-write"}
    assert adc_rights(adc_doctor(tmp_path, device)[WRITE])[0] == readiness.OK


def test_adc_system_admin_check_account_is_a_warning(tmp_path):
    device = FakeFortiADC()
    device.admins["netops-check"] = {"is-system-admin": "yes", "access-profile": "super_admin_prof"}
    status, detail = adc_rights(adc_doctor(tmp_path, device)[CHECK])
    assert status == readiness.WARNING and "is-system-admin yes" in detail and "Admin check" in detail
    assert TABLE in detail


def test_adc_read_check_account_is_ok(tmp_path):
    device = FakeFortiADC()
    assert adc_rights(adc_doctor(tmp_path, device)[CHECK])[0] == readiness.OK
    assert device.rights_queries == [
        ("netops-rw", 'show system admin "netops-rw"'),
        ("netops-check", 'show system admin "netops-check"'),
        ("netops-check", 'show system accprofile "netops-read"'),
    ]
    assert device.applied_blocks == [] and device.queries == []


def test_adc_read_write_area_on_the_check_account_is_a_warning(tmp_path):
    device = FakeFortiADC()
    device.access_profiles["netops-read"]["load-balance"] = "read-write"
    status, detail = adc_rights(adc_doctor(tmp_path, device)[CHECK])
    assert status == readiness.WARNING and "load-balance read-write" in detail


def test_adc_invisible_profile_cannot_be_verified(tmp_path):
    device = FakeFortiADC()
    device.access_profiles.clear()
    assert adc_rights(adc_doctor(tmp_path, device)[CHECK])[0] == readiness.UNVERIFIED


def test_adc_refused_read_cannot_be_verified(tmp_path):
    device = FakeFortiADC()
    device.rights_answers['show system admin "netops-check"'] = (
        "Parsing error at 'admin'\nCommand fail. Return code is -284 (CLI parsing error.)\n")
    status, detail = adc_rights(adc_doctor(tmp_path, device)[CHECK])
    assert status == readiness.UNVERIFIED and "Parsing error at 'admin'" in detail and "-284" in detail
    assert "RADIUS" not in detail


def test_own_query_reads_with_the_account_it_names(monkeypatch):
    calls = []

    def run_command(address, port, login, credential, host_key_line, command, **options):
        calls.append((address, credential.login, command))
        return SimpleNamespace(rc=1, stdout=b"Unknown action 0\n", stderr=b"")

    monkeypatch.setattr(access.ssh, "run_command", run_command)
    monkeypatch.setattr(access.hostkey, "scan", lambda address, *a, **k: "%s ssh-rsa AAAA" % address)
    handle = access.DeviceAccess.__new__(access.DeviceAccess)
    handle.device = SimpleNamespace(address="192.0.2.1", check_address="198.51.100.1", port=22,
                                    host_key_fingerprint="SHA256:x", legacy_ssh=None, platform="fortios")
    handle.credential = SimpleNamespace(login="netops-rw")
    handle.check_credential = SimpleNamespace(login="netops-check")
    handle._host_key_lines = {}
    assert handle.own_query('show system admin "netops-rw"') == "Unknown action 0\n"
    handle.own_query('show system admin "netops-check"', check=True)
    assert calls == [("192.0.2.1", "netops-rw", 'show system admin "netops-rw"'),
                     ("198.51.100.1", "netops-check", 'show system admin "netops-check"')]
