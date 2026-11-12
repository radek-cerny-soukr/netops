"""Transport classes through the real engine, netops_core SSH transport and audit.

Only the OpenSSH programs are fake: `ssh-keyscan` and `ssh` on PATH answer the way the
real clients do for an unreachable, silent, refusing or answering host, a wrong host key,
a refused password and a dropped connection (their exit codes and their own last
messages). Every read runs the real host-key scan, probe, exec or PTY session, parser
and the persisted Helper audit; no engine function is replaced.
"""
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from conftest import HOST_KEY_BLOB, LOOPBACK, PASSWORD, PORT, _target, _write_client
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, engine
from netops_helper.auth import EgressPolicy

OTHER_KEY_BLOB = "b3RoZXItaG9zdC1rZXktbWF0ZXJpYWwtb2ZmZXJlZC1CQkI="
DEVICE_TEXT = "device-banner-text-never-returned"
FAKE_SSH = '''#!/usr/bin/env python3
import json, os, sys, time
plan = json.load(open({plan!r}))
argv = sys.argv[1:]
mode = "probe" if "netops-hostkey" in argv else "pty" if "-tt" in argv else "exec"
with open({log!r}, "a") as handle:
    handle.write(json.dumps({{"program": "ssh", "mode": mode}}) + "\\n")
step = plan[mode]
if mode == "pty":
    # One terminal carries both streams, as for the real client in a PTY session.
    sys.stdout.write(step.get("banner", "") + step["said"] + "\\r\\n")
    sys.stdout.flush()
else:
    sys.stderr.write(step["said"] + "\\n")
sys.exit(step["code"])
'''
FAKE_KEYSCAN = '''#!/usr/bin/env python3
import json, sys
plan = json.load(open({plan!r}))
with open({log!r}, "a") as handle:
    handle.write(json.dumps({{"program": "ssh-keyscan"}}) + "\\n")
blob = plan["keyscan"]
if not blob:
    sys.exit(1)
sys.stdout.write("[%s]:%s ssh-ed25519 %s\\n" % (sys.argv[-1], sys.argv[sys.argv.index("-p") + 1], blob))
'''

PERMISSION_DENIED = {"code": 255, "said": "reader@127.0.0.1: Permission denied (password,keyboard-interactive)."}
CLOSED = {"code": 255, "said": "Connection closed by 127.0.0.1 port 2222"}
PTY_CLOSED = {"code": 255, "said": "Connection to 127.0.0.1 closed by remote host."}
ANSWERED_PROBE = {"code": 255, "said": "netops-hostkey@127.0.0.1: Permission denied (publickey,password)."}
UNUSED = {"code": 99, "said": "this client step must not run"}


def _probe(message):
    return {"code": 255, "said": "ssh: connect to host 127.0.0.1 port 2222: " + message}


# class -> (keyscan blob, probe, exec, pty); exec and pty run only after a matching key.
SCENARIOS = {
    "unreachable": ("", _probe("No route to host"), UNUSED, UNUSED),
    "timeout": ("", _probe("Connection timed out"), UNUSED, UNUSED),
    "connection_refused": ("", _probe("Connection refused"), UNUSED, UNUSED),
    "host_key_unavailable": ("", ANSWERED_PROBE, UNUSED, UNUSED),
    "host_key_mismatch": (OTHER_KEY_BLOB, UNUSED, UNUSED, UNUSED),
    "auth": (HOST_KEY_BLOB, UNUSED, PERMISSION_DENIED, {**PERMISSION_DENIED, "banner": DEVICE_TEXT + "\r\n"}),
    "disconnected": (HOST_KEY_BLOB, UNUSED, CLOSED, PTY_CLOSED),
}
CLASSES = list(SCENARIOS)
BANNER = "Banner: Permission denied to anyone without a contract; host key verification failed elsewhere."
# A device banner printed by the client before its own closing message never decides the class.
SCENARIOS["banner_then_closed"] = (HOST_KEY_BLOB, UNUSED, {"code": 255, "said": BANNER + "\n" + CLOSED["said"]},
                                   {"code": 255, "said": BANNER + "\r\n" + PTY_CLOSED["said"]})
SCENARIOS["banner_then_refused_login"] = (HOST_KEY_BLOB, UNUSED,
                                          {"code": 255, "said": "Banner: connection reset by policy\n" + PERMISSION_DENIED["said"]},
                                          {"code": 255, "said": "Banner: connection reset by policy\r\n" + PERMISSION_DENIED["said"]})
# A banner that names the negotiation marker before a refused login: the key exchange and the host key
# succeeded, so the class is auth and nothing suggests a legacy algorithm profile.
NO_MATCHING_BANNER = "Authorized access only: no matching access request means permission denied."
SCENARIOS["banner_naming_no_matching"] = (HOST_KEY_BLOB, UNUSED,
                                          {"code": 255, "said": NO_MATCHING_BANNER + "\n" + PERMISSION_DENIED["said"]},
                                          {"code": 255, "said": NO_MATCHING_BANNER + "\r\n" + PERMISSION_DENIED["said"]})
NEGOTIATION = {"code": 255, "said": "Unable to negotiate with 127.0.0.1 port 2222: no matching host key type found."
                                    " Their offer: ssh-rsa"}
SCENARIOS["negotiation"] = (HOST_KEY_BLOB, UNUSED, NEGOTIATION, NEGOTIATION)
NETWORK_CLASSES = ("unreachable", "timeout", "connection_refused", "host_key_unavailable")


@pytest.fixture()
def fake_openssh(tmp_path, monkeypatch):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    plan, log = tmp_path / "plan.json", tmp_path / "clients.jsonl"
    _write_client(binaries, "ssh", FAKE_SSH.format(plan=str(plan), log=str(log)))
    _write_client(binaries, "ssh-keyscan", FAKE_KEYSCAN.format(plan=str(plan), log=str(log)))
    monkeypatch.setenv("PATH", f"{binaries}:{os.environ['PATH']}")
    audit = tmp_path / "operations.jsonl"
    monkeypatch.setattr(helper_audit, "_RECORDER", Recorder(audit, "helper"))
    engine._SSH_PAGE_CACHE.clear()

    def use(code):
        keyscan, probe, exec_step, pty_step = SCENARIOS[code]
        plan.write_text(json.dumps({"keyscan": keyscan, "probe": probe, "exec": exec_step, "pty": pty_step}))

    def clients():
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def events():
        return [json.loads(line) for line in audit.read_text().splitlines()]

    yield use, clients, events
    engine._SSH_PAGE_CACHE.clear()


def _egress(**flags):
    return EgressPolicy(addresses=(LOOPBACK,), tcp_ports=(PORT,), **flags)


def switch_auth():
    return replace(_target("extreme_exos", "mac_table"), device_types=("switch",), egress=_egress())


def adc_auth():
    return replace(
        _target("fortiadc", "system_status"), egress=_egress(allow_icmp=True),
        read_inventory={"config_access": ("read",), "adc_virtual_servers": ("VS_APP_HTTP",), "adc_vdoms": ("root",),
                        "addresses": ("192.0.2.11",), "diagnostic_virtual_servers": ("VS_APP_HTTP",),
                        "diagnostic_recipes": ("ping", "system_event_logs", "session_list")},
    )


def fortios_auth():
    return replace(_target("fortinet", "system_status"), egress=_egress(allow_icmp=True))


def _private_free(*values):
    text = json.dumps(values)
    for private in (PASSWORD, DEVICE_TEXT, "No route to host", "Permission denied", "closed by", "127.0.0.1 port"):
        assert private not in text


def _failed_details(events, event):
    return [e.get("detail") for e in events if e["event"] == event and e["status"] == "failed"]


def _expected_clients(code, transports):
    """The fake clients a read runs: the scan of three key types, then the probe or one transport."""
    scans = [{"program": "ssh-keyscan"}] * (3 if not SCENARIOS[code][0] else 1)
    if code in NETWORK_CLASSES:
        return scans + [{"program": "ssh", "mode": "probe"}]
    if code == "host_key_mismatch":
        return [{"program": "ssh-keyscan"}] * 3
    return scans + [{"program": "ssh", "mode": mode} for mode in transports]


@pytest.mark.parametrize("code", CLASSES)
def test_switch_read_names_the_real_cause(fake_openssh, code):
    use, clients, events = fake_openssh
    use(code)
    result = engine.switch_read(switch_auth(), "mac_entry")
    assert result["ok"] is False and result["records"] == []
    assert result["status"] == ("timeout" if code == "timeout" else "transport_error")
    assert result["error_code"] == code
    assert result["error"] == engine._TRANSPORT_ADVICE[code]
    assert clients() == _expected_clients(code, ["exec"])
    assert _failed_details(events(), "normalized_query") == [code]
    assert _failed_details(events(), "switch_read") == [code]
    _private_free(result, events())


@pytest.mark.parametrize("code", CLASSES)
def test_locate_endpoint_missing_names_the_cause(fake_openssh, code):
    use, _, events = fake_openssh
    use(code)
    auth = switch_auth()
    result = engine._locate_endpoint_run([auth], "00:00:5e:00:53:fe")
    assert {"vantage": auth.alias, "table": "mac_entry",
            "reason": "timeout" if code == "timeout" else "transport_error",
            "error_code": code, "error": engine._TRANSPORT_ADVICE[code]} in result["missing"]
    assert code in _failed_details(events(), "locate_endpoint_read")
    _private_free(result, events())


@pytest.mark.parametrize("platform,query,auth", [
    ("extreme_exos", "version", lambda: replace(switch_auth(), enabled_queries=("version",))),
    ("fortiadc", "system_status", adc_auth),
], ids=["switch", "fortiadc"])
@pytest.mark.parametrize("code", CLASSES)
def test_ssh_read_failure_has_class_advice_and_audit_detail(fake_openssh, code, platform, query, auth):
    use, clients, events = fake_openssh
    use(code)
    result = engine.ssh_read(auth(), platform, query, None, 0, 16000)
    assert result["ok"] is False
    assert (result["error_code"], result["error"]) == (code, engine._TRANSPORT_ADVICE[code])
    assert clients() == _expected_clients(code, ["exec"])
    assert _failed_details(events(), "ssh_read") == [code]
    _private_free(result, events())


@pytest.mark.parametrize("recipe,address,count", [
    ("ping", "192.0.2.11", 3), ("system_event_logs", "", 10), ("session_list", "VS_APP_HTTP", 10),
])
@pytest.mark.parametrize("code", CLASSES)
def test_fortiadc_diagnostics_return_the_class_instead_of_a_role_failure(fake_openssh, code, recipe, address, count):
    use, clients, events = fake_openssh
    use(code)
    result = engine.fortios_diagnostics(adc_auth(), recipe, address, "", count=count, timeout=5, max_bytes=16000)
    assert result == {"ok": False, "target": "wire-test", "platform": "fortiadc", "recipe": recipe,
                      "error_code": code, "error": engine._TRANSPORT_ADVICE[code]}
    assert clients() == _expected_clients(code, ["pty"])
    assert _failed_details(events(), "fortios_diagnostics") == [code]
    _private_free(result, events())


@pytest.mark.parametrize("code", CLASSES)
def test_fortiadc_config_read_returns_the_class(fake_openssh, code):
    use, clients, events = fake_openssh
    use(code)
    result = engine.config_read(adc_auth(), "fortiadc", "all", include_all=True, redaction="full")
    assert result == {"ok": False, "target": "wire-test", "platform": "fortiadc", "section": "all",
                      "error_code": code, "error": engine._TRANSPORT_ADVICE[code]}
    assert clients() == _expected_clients(code, ["exec"])
    assert _failed_details(events(), "config_read") == [code]
    _private_free(result, events())


@pytest.mark.parametrize("code", CLASSES)
def test_triage_slb_identity_failure_explains_the_class(fake_openssh, code):
    use, _, events = fake_openssh
    use(code)
    result = engine.triage_slb(adc_auth(), "VS_APP_HTTP")
    advice = engine._TRANSPORT_ADVICE[code]
    reason = "timeout" if code == "timeout" else "transport_error"
    assert (result["ok"], result["error_code"], result["error"], result["failed_step"], result["verdict"]) == (
        False, code, advice, "system_status", "incomplete")
    assert result["missing"] == [{"step": "system_status", "reason": reason, "error_code": code, "error": advice}]
    assert _failed_details(events(), "triage_slb") == [code]
    _private_free(result, events())


@pytest.mark.parametrize("code", CLASSES)
def test_fortios_triage_and_diagnostics_carry_the_class(fake_openssh, code):
    use, _, events = fake_openssh
    use(code)
    auth = replace(fortios_auth(), read_inventory={"diagnostic_recipes": ("ping",), "addresses": ("192.0.2.11",),
                                                    "interfaces": ("port1",)})
    advice = engine._TRANSPORT_ADVICE[code]
    triage = engine.triage_health(auth)
    assert (triage["ok"], triage["error_code"], triage["error"], triage["verdict"]) == (
        False, code, advice, "incomplete")
    assert {"step": "system_status", "reason": "timeout" if code == "timeout" else "transport_error",
            "error_code": code, "error": advice} in triage["missing"]
    diagnostic = engine.fortios_diagnostics(auth, "ping", "192.0.2.11", "port1")
    assert diagnostic == {"ok": False, "target": "wire-test", "recipe": "ping", "error_code": code, "error": advice}
    assert _failed_details(events(), "triage_health") == [code]
    assert _failed_details(events(), "triage_health_read") == [code]
    assert _failed_details(events(), "fortios_diagnostics") == [code]
    _private_free(triage, diagnostic, events())


def test_the_wrong_password_never_points_at_the_host_key(fake_openssh):
    use, _, _ = fake_openssh
    use("auth")
    for result in (engine.ssh_read(adc_auth(), "fortiadc", "system_status", None, 0, 16000),
                   engine.triage_slb(adc_auth(), "VS_APP_HTTP"),
                   engine.fortios_diagnostics(adc_auth(), "ping", "192.0.2.11", "", count=3, timeout=5)):
        assert result["error_code"] == "auth"
        assert "pin" not in result["error"] and "host key was verified" in result["error"]


def test_unreachable_target_never_points_at_the_pin(fake_openssh):
    use, _, _ = fake_openssh
    use("unreachable")
    result = engine.switch_read(replace(switch_auth(), enabled_queries=("ports",)), "interface")
    assert result["error_code"] == "unreachable"
    assert "before changing the account or the pinned host key" in result["error"]


@pytest.mark.parametrize("code", CLASSES)
def test_schema_read_returns_the_class(fake_openssh, tmp_path, monkeypatch, code):
    from hashlib import sha256
    from conftest import HOST_KEY_PIN
    from test_schema_read import auth as schema_auth, document
    use, clients, events = fake_openssh
    use(code)
    library = tmp_path / "library.json"
    library.write_text(json.dumps(document()))
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"format": 1, "targets": {"device-a": {
        "schema": "library.json", "sha256": sha256(library.read_bytes()).hexdigest(),
        "host_key_fingerprint": HOST_KEY_PIN}}}))
    monkeypatch.setenv("NETOPS_SCHEMA_REGISTRY", str(registry))
    auth = replace(schema_auth(), host=LOOPBACK, port=PORT, host_key_fingerprint=HOST_KEY_PIN, egress=_egress())
    result = engine.schema_read(auth, "firewall address", "get", None, None, 0, 1000)
    assert result == {"ok": False, "target": "device-a", "platform": "fortinet", "query": "schema_read",
                      "error_code": code, "error": engine._TRANSPORT_ADVICE[code]}
    assert clients() == _expected_clients(code, ["exec"])
    assert _failed_details(events(), "schema_read") == [code]
    _private_free(result, events())


@pytest.mark.parametrize("scenario,code", [("banner_then_closed", "disconnected"), ("banner_then_refused_login", "auth")])
def test_a_device_banner_does_not_steer_the_class(fake_openssh, scenario, code):
    use, _, events = fake_openssh
    use(scenario)
    assert engine.switch_read(switch_auth(), "mac_entry")["error_code"] == code
    assert engine.ssh_read(adc_auth(), "fortiadc", "system_status", None, 0, 16000)["error_code"] == code
    diagnostic = engine.fortios_diagnostics(adc_auth(), "ping", "192.0.2.11", "", count=3, timeout=5)
    assert diagnostic["error_code"] == code
    assert "Banner" not in json.dumps([diagnostic, events()])


@pytest.mark.parametrize("platform,recipe,address,interface,count", [
    ("fortiadc", "ping", "192.0.2.11", "", 3), ("fortiadc", "system_event_logs", "", "", 10),
    ("fortinet", "ping", "192.0.2.11", "port1", 3),
], ids=["fortiadc-ping", "fortiadc-logs", "fortios-ping"])
def test_a_diagnostic_target_name_that_does_not_resolve_is_dns(fake_openssh, monkeypatch, platform, recipe,
                                                               address, interface, count):
    import socket
    _, clients, events = fake_openssh
    def unresolved(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known " + DEVICE_TEXT)
    monkeypatch.setattr(engine.socket, "getaddrinfo", unresolved)
    base = adc_auth() if platform == "fortiadc" else replace(
        fortios_auth(), read_inventory={"diagnostic_recipes": ("ping",), "addresses": ("192.0.2.11",),
                                        "interfaces": ("port1",)})
    auth = replace(base, host="device.example.invalid", egress=replace(base.egress, allow_dns=True))
    result = engine.fortios_diagnostics(auth, recipe, address, interface, count=count, timeout=5)
    assert result == {"ok": False, "target": "wire-test", **({"platform": "fortiadc"} if platform == "fortiadc" else {}),
                      "recipe": recipe, "error_code": "dns", "error": engine._TRANSPORT_ADVICE["dns"]}
    assert clients() == []
    assert _failed_details(events(), "fortios_diagnostics") == ["dns"]
    _private_free(result, events())


def test_an_escaping_transport_exception_is_audited_by_its_class_and_a_local_one_by_its_type(fake_openssh):
    from netops_core import session as core_session
    _, _, events = fake_openssh

    @engine._audit_device_call
    def lost_session(auth):
        raise RuntimeError("wrapper") from core_session.SessionError(
            "the session ended", 0, "Connection to 127.0.0.1 closed by remote host.")

    @engine._audit_device_call
    def local_refusal(auth):
        raise ValueError("a local refusal before any connection")

    with pytest.raises(RuntimeError):
        lost_session(switch_auth())
    with pytest.raises(ValueError):
        local_refusal(switch_auth())
    assert _failed_details(events(), "lost_session") == ["disconnected"]
    assert _failed_details(events(), "local_refusal") == ["ValueError"]


def test_a_banner_naming_no_matching_keeps_the_refused_login(fake_openssh):
    use, clients, events = fake_openssh
    use("banner_naming_no_matching")
    advice = engine._TRANSPORT_ADVICE["auth"]
    reads = [(engine.ssh_read(adc_auth(), "fortiadc", "system_status", None, 0, 16000), "ssh_read"),
             (engine.ssh_read(replace(switch_auth(), enabled_queries=("version",)), "extreme_exos", "version",
                              None, 0, 16000), "ssh_read"),
             (engine.switch_read(switch_auth(), "mac_entry"), "switch_read")]
    for result, _ in reads:
        assert result["ok"] is False
        assert (result["error_code"], result["error"]) == ("auth", advice)
        assert "legacy_ssh" not in json.dumps(result)
    assert [c["mode"] for c in clients() if c["program"] == "ssh"] == ["exec"] * 3
    assert _failed_details(events(), "ssh_read") == ["auth", "auth"]
    assert _failed_details(events(), "switch_read") == ["auth"]
    diagnostic = engine.fortios_diagnostics(adc_auth(), "ping", "192.0.2.11", "", count=3, timeout=5)
    assert (diagnostic["error_code"], diagnostic["error"]) == ("auth", advice)
    assert _failed_details(events(), "fortios_diagnostics") == ["auth"]
    assert "negotiation" not in json.dumps(events())
    assert "Authorized access" not in json.dumps([reads, diagnostic, events()])
    _private_free(reads, diagnostic, events())


def test_a_real_negotiation_failure_still_names_the_legacy_profile(fake_openssh):
    use, _, events = fake_openssh
    use("negotiation")
    result = engine.ssh_read(adc_auth(), "fortiadc", "system_status", None, 0, 16000)
    assert (result["error_code"], result["error"]) == ("negotiation", engine._TRANSPORT_ADVICE["negotiation"])
    assert _failed_details(events(), "ssh_read") == ["negotiation"]
    enrolled = engine.ssh_read(replace(adc_auth(), legacy_ssh="rsa-sha1"), "fortiadc", "system_status",
                               None, 0, 16000)
    assert enrolled["error_code"] == "negotiation"


def test_a_verified_cause_beneath_the_legacy_wrapper_decides(fake_openssh):
    from netops_core import ssh
    _, _, events = fake_openssh

    @engine._audit_device_call
    def wrapped_refusal(auth):
        refusal = ssh.SshError("ssh failed", 255, NO_MATCHING_BANNER + " " + PERMISSION_DENIED["said"],
                               PERMISSION_DENIED["said"])
        raise engine._legacy_ssh_required(auth) from refusal

    @engine._audit_device_call
    def wrapped_negotiation(auth):
        raise engine._legacy_ssh_required(auth) from ssh.SshError("ssh failed", 255, NEGOTIATION["said"],
                                                                  NEGOTIATION["said"])

    for call in (wrapped_refusal, wrapped_negotiation):
        with pytest.raises(engine.LegacySshProfileRequired):
            call(switch_auth())
    assert _failed_details(events(), "wrapped_refusal") == ["auth"]
    assert _failed_details(events(), "wrapped_negotiation") == ["negotiation"]


EAI_CASES = [
    ("EAI_NONAME", "Name or service not known"),
    ("EAI_NODATA", "No address associated with hostname"),
    ("EAI_FAIL", "Non-recoverable failure in name resolution"),
    ("EAI_AGAIN", "Temporary failure in name resolution"),
    # The type decides before any text: resolver words that look like another class do not steer it.
    ("EAI_FAIL", "Connection refused; timed out"),
]


@pytest.mark.parametrize("name,text", EAI_CASES, ids=[f"{n}-{i}" for i, (n, _) in enumerate(EAI_CASES)])
def test_every_resolver_failure_of_the_target_name_is_dns(fake_openssh, monkeypatch, name, text):
    import socket
    _, clients, events = fake_openssh
    number = getattr(socket, name, None)
    if number is None:
        pytest.skip(f"{name} is not defined on this platform")

    def unresolved(*args, **kwargs):
        raise socket.gaierror(number, text + " " + DEVICE_TEXT)

    monkeypatch.setattr(engine.socket, "getaddrinfo", unresolved)
    base = adc_auth()
    auth = replace(base, host="device.example.invalid", egress=replace(base.egress, allow_dns=True))
    result = engine.ssh_read(auth, "fortiadc", "system_status", None, 0, 16000)
    assert result["ok"] is False
    assert (result["error_code"], result["error"]) == ("dns", engine._TRANSPORT_ADVICE["dns"])
    switch = replace(switch_auth(), host="device.example.invalid", egress=replace(switch_auth().egress, allow_dns=True))
    assert engine.switch_read(switch, "mac_entry")["error_code"] == "dns"
    assert clients() == []
    assert _failed_details(events(), "ssh_read") == ["dns"]
    assert _failed_details(events(), "switch_read") == ["dns"]
    _private_free(result, events())
    assert text not in json.dumps([result, events()])
