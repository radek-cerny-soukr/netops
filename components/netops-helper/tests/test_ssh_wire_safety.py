"""Wire-level regression over a substituted OpenSSH client: argv, environment and bytes."""

from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest

from conftest import (
    EXEC_CLIENT,
    EXEC_OUTPUT,
    HOST_KEY_BLOB,
    HOST_KEY_PIN,
    KNOWN_HOSTS_LINE,
    LOGIN,
    LOOPBACK,
    PASSWORD,
    PORT,
    RUCKUS_BANNER,
    RUCKUS_OUTPUT,
    _calls,
    _plain_query,
    _ruckus_wire,
    _target,
    _write_client,
)


_REQUIRE_RUNTIME = os.environ.get("NETOPS_REQUIRE_RUNTIME_TESTS") == "1"
_REQUIRED_MODULES = ("icmplib",)
_MISSING_RUNTIME = tuple(
    name for name in _REQUIRED_MODULES if importlib.util.find_spec(name) is None
)
if _MISSING_RUNTIME:
    message = "project runtime dependencies are missing: " + ", ".join(_MISSING_RUNTIME)
    if _REQUIRE_RUNTIME:
        raise RuntimeError(message)
    pytest.skip(message, allow_module_level=True)

import netops_helper.engine as engine


BASE_OPTIONS = (
    "StrictHostKeyChecking=yes",
    "IdentitiesOnly=yes",
    "ClearAllForwardings=yes",
    "ProxyCommand=none",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "ControlPath=none",
)
LEGACY_OPTIONS = ("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa")
FORBIDDEN_ON_THE_WIRE = (
    "config", "configure", "edit", "set ", "unset ", "next", "end", "save",
    "commit", "write", "delete", "execute", "reload", "reboot", "clear",
    "debug", "terminal ", "exit", "quit", "remote_ap_cli",
)


def _options(argv: list[str]) -> list[str]:
    return [argv[index + 1] for index, item in enumerate(argv) if item == "-o"]


def _assert_hardened(argv: list[str], secret: str, environment: dict) -> None:
    assert argv[0] == "-F" and argv[1] == "/dev/null", argv
    options = _options(argv)
    for option in BASE_OPTIONS:
        assert option in options, option
    assert any(option.startswith("UserKnownHostsFile=") for option in options)
    assert f"{LOGIN}@{LOOPBACK}" in argv
    assert "-p" in argv and argv[argv.index("-p") + 1] == str(PORT)
    assert all(secret not in item for item in argv), argv
    assert all(secret not in str(value) for value in environment.values())
    assert set(environment) <= {
        "PATH", "HOME", "LC_ALL",
        "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY", "NETOPS_ASKPASS_FILE",
    }, sorted(environment)


EXEC_PLATFORMS = tuple(
    platform
    for platform, transport in sorted(engine._SSH_TRANSPORTS.items())
    if transport == "exec"
)


@pytest.mark.parametrize("platform", EXEC_PLATFORMS)
def test_every_exec_platform_sends_its_preamble_and_the_catalog_command(
    wire, platform,
) -> None:
    query_name, command = _plain_query(platform)
    target = _target(platform, query_name)
    result = engine.ssh_read(target, platform, query_name, {}, 0, 16_000)

    assert result["ok"] is True, result
    assert result["transport"] == "exec"
    assert result["rc"] == 0
    assert EXEC_OUTPUT in result["untrusted_device_output"]

    calls = _calls(wire)
    expected = [*engine._PLATFORM_PREAMBLE.get(platform, ()), command]
    assert calls[0]["argv"][0] == "-T", calls[0]["argv"]
    assert calls[0]["argv"][-1] == LOOPBACK
    assert [call["argv"][-1] for call in calls[1:]] == expected
    for call in calls[1:]:
        _assert_hardened(call["argv"], PASSWORD, call["env"])
        assert call["known_hosts"] == KNOWN_HOSTS_LINE + "\n"
        assert call["stdin_isatty"] is False
        assert LEGACY_OPTIONS[0] not in _options(call["argv"])
    sent = " ".join(call["argv"][-1] for call in calls[1:]).lower()
    for forbidden in FORBIDDEN_ON_THE_WIRE:
        assert forbidden not in sent or forbidden in " ".join(expected).lower(), forbidden


def test_the_password_reaches_the_client_only_through_the_askpass_file(wire) -> None:
    import hashlib

    target = _target("linux", "hostname")
    assert engine.ssh_read(target, "linux", "hostname", {}, 0, 16_000)["ok"] is True
    call = _calls(wire)[-1]
    assert call["askpass_sha256"] == hashlib.sha256(PASSWORD.encode("utf-8")).hexdigest()
    assert call["askpass_mode"] == "0o600"
    assert call["env"]["SSH_ASKPASS_REQUIRE"] == "force"
    assert "BatchMode=no" in _options(call["argv"])
    assert "NumberOfPasswordPrompts=1" in _options(call["argv"])
    assert "PubkeyAuthentication=no" in _options(call["argv"])
    assert "-i" not in call["argv"]


def test_a_key_reaches_the_client_only_as_a_private_file(wire) -> None:
    import hashlib

    key = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "replace-me\n" * 4 + "-----END OPENSSH PRIVATE KEY-----\n"
    target = _target("linux", "hostname", credential_kind="ssh-key", secret=key)
    assert engine.ssh_read(target, "linux", "hostname", {}, 0, 16_000)["ok"] is True
    call = _calls(wire)[-1]
    assert call["identity_sha256"] == hashlib.sha256(key.encode("utf-8")).hexdigest()
    assert call["identity_mode"] == "0o600"
    assert "BatchMode=yes" in _options(call["argv"])
    assert not os.path.exists(call["argv"][call["argv"].index("-i") + 1])
    _assert_hardened(call["argv"], key, call["env"])
    assert "SSH_ASKPASS" not in call["env"]


def test_the_legacy_options_appear_only_with_the_enrolled_profile(wire) -> None:
    plain = _target("linux", "hostname")
    engine.ssh_read(plain, "linux", "hostname", {}, 0, 16_000)
    assert all(
        option not in _options(_calls(wire)[-1]["argv"]) for option in LEGACY_OPTIONS
    )

    legacy = _target("linux", "hostname", legacy_ssh="rsa-sha1")
    engine.ssh_read(legacy, "linux", "hostname", {}, 0, 16_000)
    options = _options(_calls(wire)[-1]["argv"])
    for option in LEGACY_OPTIONS:
        assert option in options
    for option in BASE_OPTIONS:
        assert option in options
    assert options.index("StrictHostKeyChecking=yes") < options.index(LEGACY_OPTIONS[0])


def test_the_exec_client_is_given_no_configuration_file_of_the_host(wire) -> None:
    engine.ssh_read(_target("linux", "hostname"), "linux", "hostname", {}, 0, 16_000)
    for call in _calls(wire)[1:]:
        assert call["argv"][:2] == ["-F", "/dev/null"]


PROMPT_NAME = "device-a"
PROMPTED_OUTPUT = (
    f"{PROMPT_NAME} $ Version: 8.0.0\n"
    "Serial-Number: replace-me\n"
    f"{PROMPT_NAME} $ \n"
)
PROMPTED_BODY = "Version: 8.0.0\nSerial-Number: replace-me\n"


def test_a_read_only_prompt_is_cleaned_out_of_the_answer(wire) -> None:
    _write_client(
        wire["binaries"], "ssh",
        EXEC_CLIENT.format(log=str(wire["log"]), output=PROMPTED_OUTPUT, code=0),
    )
    query_name, _ = _plain_query("fortinet")
    result = engine.ssh_read(
        _target("fortinet", query_name), "fortinet", query_name, {}, 0, 16_000,
    )
    assert result["ok"] is True, result
    body = result["untrusted_device_output"]
    assert body.startswith("Version: 8.0.0")
    assert body == PROMPTED_BODY
    assert not body.rstrip("\n").endswith("$")
    assert PROMPT_NAME not in body


def test_a_platform_without_a_prompt_table_keeps_every_byte(wire) -> None:
    _write_client(
        wire["binaries"], "ssh",
        EXEC_CLIENT.format(log=str(wire["log"]), output=PROMPTED_OUTPUT, code=0),
    )
    result = engine.ssh_read(
        _target("linux", "hostname"), "linux", "hostname", {}, 0, 16_000,
    )
    assert result["untrusted_device_output"] == PROMPTED_OUTPUT


def test_a_nonzero_exit_status_still_returns_the_answer(wire, monkeypatch) -> None:
    _write_client(
        wire["binaries"], "ssh",
        EXEC_CLIENT.format(log=str(wire["log"]), output=EXEC_OUTPUT + "\n", code=250),
    )
    target = _target("extreme_exos", "version")
    result = engine.ssh_read(target, "extreme_exos", "version", {}, 0, 16_000)
    assert result["ok"] is True, result
    assert result["rc"] == 250
    assert EXEC_OUTPUT in result["untrusted_device_output"]


def test_a_client_failure_is_refused_and_names_no_secret(wire) -> None:
    _write_client(
        wire["binaries"], "ssh",
        EXEC_CLIENT.format(log=str(wire["log"]), output="", code=255),
    )
    target = _target("linux", "hostname")
    result = engine.ssh_read(target, "linux", "hostname", {}, 0, 16_000)
    assert result["ok"] is False
    assert PASSWORD not in json.dumps(result)


def test_the_access_point_is_driven_on_a_terminal_and_the_login_never_leaks(wire) -> None:
    _ruckus_wire(wire)
    target = _target("ruckus_unleashed", "system_info", legacy_ssh="rsa-sha1")
    result = engine.ssh_read(
        target, "ruckus_unleashed", "system_info", {}, 0, 16_000,
    )

    assert result["ok"] is True, result
    assert result["transport"] == "pty"
    assert result["rc"] is None
    assert result["untrusted_device_output"] == RUCKUS_OUTPUT
    for leaked in (PASSWORD, LOGIN, "Please login", "Password", RUCKUS_BANNER, "ruckus"):
        assert leaked not in result["untrusted_device_output"], leaked

    calls = _calls(wire)
    assert len(calls) == 2
    client = calls[1]
    assert client["argv"][:3] == ["-F", "/dev/null", "-tt"]
    assert client["stdin_isatty"] is True
    assert client["known_hosts"] == KNOWN_HOSTS_LINE + "\n"
    _assert_hardened(client["argv"], PASSWORD, client["env"])
    for option in LEGACY_OPTIONS:
        assert option in _options(client["argv"])

    sent = wire["transcript"].read_text(encoding="utf-8").splitlines()
    assert sent == [LOGIN, PASSWORD, "enable", "show sysinfo"]
    for forbidden in ("config", "exit", "quit", "reboot", "set ", "remote_ap_cli"):
        assert all(forbidden not in line.lower() for line in sent), forbidden


def test_the_login_phase_of_the_access_point_stays_out_of_error_and_audit(
    wire, monkeypatch,
) -> None:
    _ruckus_wire(wire)
    events: list[dict] = []
    monkeypatch.setattr(
        engine, "record",
        lambda event, **fields: events.append({"event": event, **fields}),
    )
    target = _target("ruckus_unleashed", "wlans", legacy_ssh="rsa-sha1")
    result = engine.ssh_read(target, "ruckus_unleashed", "wlans", {}, 0, 16_000)
    assert result["ok"] is True, result
    written = json.dumps(events)
    for leaked in (PASSWORD, LOGIN, "Please login", RUCKUS_BANNER, RUCKUS_OUTPUT):
        assert leaked not in written, leaked
    assert [event["status"] for event in events] == ["started", "ok"]
    assert "transport" not in events[0]
    assert events[1]["transport"] == "pty"
    assert "rc" not in events[1]
    assert all("untrusted_device_output" not in event for event in events)


def test_a_login_that_never_answers_names_no_transcript(wire, monkeypatch) -> None:
    _write_client(
        wire["binaries"], "ssh",
        "#!/usr/bin/env python3\nimport sys, time\nsys.stdout.write('garbage banner')\n"
        "sys.stdout.flush()\ntime.sleep(5)\n",
    )
    monkeypatch.setattr(engine, "_SSH_LOGIN_TIMEOUT_SECONDS", 1.0)
    target = _target("ruckus_unleashed", "system_info", legacy_ssh="rsa-sha1")
    result = engine.ssh_read(
        target, "ruckus_unleashed", "system_info", {}, 0, 16_000,
    )
    assert result["ok"] is False
    assert "garbage banner" not in result["error"]
    assert PASSWORD not in result["error"]
