"""Count clients while replaying Fortinet command answers on the local SSH wire."""

import base64
from dataclasses import replace

import pytest

from conftest import FORTIADC_STATUS, FORTIOS_STATUS, KEYSCAN_CLIENT, _target, _write_client
from netops_core.hostkey import fingerprint_of
from netops_helper import engine, fortigate_tables
from netops_helper.auth import EgressPolicy

KEY = base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
PROMPT = "test-fortinet # "
CLIENT = r"""
import os
import sys
import time
import tty

with open(EVENTS, "a") as events:
    events.write("ssh\n")
if "-tt" not in sys.argv:
    command = sys.argv[-1]
    sys.stdout.write(ANSWERS.get(command, ""))
    sys.exit(0)
tty.setraw(0)
os.write(1, PROMPT.encode())
answers = ANSWERS if open(EVENTS).read().count("ssh\n") == 1 else REPAIR
for line in sys.stdin.buffer:
    command = line.decode().rstrip("\n")
    if not command:
        os.write(1, ("\r\n" + PROMPT).encode())
        continue
    with open(COMMANDS, "a") as commands:
        commands.write(command + "\n")
    answer = answers.get(command, "")
    if answer is None:
        sys.exit(255)
    if isinstance(answer, dict):
        os.write(1, (command + "\r\n" + PROMPT).encode())
        time.sleep(0.25)
        answer = "\n" + answer["tail"]
        command = ""
    if isinstance(answer, tuple):
        answer, PROMPT = answer
    if isinstance(answer, list):
        first, answer = answer
        os.write(1, (command + "\r\n" + first).encode() + b"--More-- \r")
        assert os.read(0, 1) == b" "
        os.write(1, b" " * 9 + b"\r")
        command = ""
    if answer and not answer.endswith("\n"):
        answer += "\n"
    echo = command + "\n" if command else ""
    os.write(1, (echo + answer + PROMPT).replace("\n", "\r\n").encode())
"""


@pytest.fixture
def replay(wire, tmp_path, monkeypatch):
    events, commands = tmp_path / "events", tmp_path / "commands"
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    def install(platform, answers, inventory=None, *, prompt=PROMPT, repair=None):
        status = FORTIOS_STATUS if platform == "fortinet" else FORTIADC_STATUS
        variables = dict(EVENTS=str(events), COMMANDS=str(commands), PROMPT=prompt,
                         ANSWERS={"get system status": status, **answers},
                         REPAIR={"get system status": status, **(repair or {})})
        script = "#!/usr/bin/env python3\n" + "".join(f"{key} = {value!r}\n" for key, value in variables.items())
        _write_client(wire["binaries"], "ssh", script + CLIENT)
        _write_client(wire["binaries"], "ssh-keyscan",
                      KEYSCAN_CLIENT.format(log=str(events), blob=KEY))
        target = _target(platform, "system_status")
        options = {"host_key": "ssh-ed25519 " + KEY} if hasattr(target, "host_key") else {}
        return replace(target, host_key_fingerprint=fingerprint_of(KEY),
                       enabled_queries=tuple(engine.READ_QUERIES[platform]), read_inventory=inventory or {},
                       egress=EgressPolicy(addresses=(target.host,), tcp_ports=(target.port,)), **options)

    def verify(expected=1):
        starts = events.read_text().splitlines()
        assert starts.count("ssh") == expected, f"ssh starts: {starts.count('ssh')}"
        assert len(starts) == expected, "unexpected ssh-keyscan start"
        return commands.read_text().splitlines()

    return install, verify


@pytest.mark.parametrize("platform", ["fortinet", "fortiadc"])
@pytest.mark.parametrize("query", ["system_status", "system_performance"])
def test_ssh_read(replay, platform, query):
    install, verify = replay
    if platform == "fortinet" and query == "system_performance":
        query = "performance"
    command = engine.READ_QUERIES[platform][query].command
    extra = {command: "CPU states: 2% user\n"} if query != "system_status" else {}
    auth = install(platform, extra)
    result = engine.ssh_read(auth, platform, query, {}, 0, 16000)
    assert result["ok"], result
    assert verify() == ["get system status"] + ([command] if extra else [])


def test_interface_list_uses_one_connection_for_telemetry(replay):
    install, verify = replay
    query = fortigate_tables.INTERFACE_LIST_QUERY
    command = engine.READ_QUERIES["fortinet"][query].command
    auth = install("fortinet", {command: "== [ port1 ]\nname: port1 mode: static ip: 192.0.2.1 255.255.255.0 status: up\n"})
    result = engine.ssh_read(auth, "fortinet", query, {}, 0, 16000)
    assert result["ok"], result
    commands = verify()
    assert commands.count(fortigate_tables.INTERFACE_COUNTERS_COMMAND) == 2
    assert commands.count(fortigate_tables.INTERFACE_SPEED_COMMAND) == 1


def test_fortiadc_interface_list_with_live_read_only_prompt(replay):
    install, verify = replay
    command = "get system interface"
    # Sanitized fortiadc-kvm netops-read prompt captured in a live acceptance run.
    auth = install("fortiadc", {command: "== [ port1 ]\nname: port1\n"}, prompt="LLLLLLLL-LLL $ ")
    result = engine.ssh_read(auth, "fortiadc", "interface_list", {}, 0, 16000)
    assert result["ok"], result
    assert verify() == ["get system status", command]


def test_config_read(replay):
    install, verify = replay
    section = "system interface"
    command = "show " + section
    auth = install("fortinet", {command: "config system interface\n edit port1\n set description example\n next\nend\n"},
                   {"config_access": ("read",)})
    result = engine.config_read(auth, "fortios", section)
    assert result["ok"], result
    assert "set description <REDACTED>" in result["untrusted_device_output"]
    assert verify() == ["get system status", command]


def test_triage_health(replay):
    install, verify = replay
    auth = install("fortinet", {})
    engine.triage_health(auth)
    commands = verify()
    assert len(commands) > 1
    assert commands[0] == "get system status"


def test_diagnostic(replay):
    install, verify = replay
    auth = install("fortiadc", {
        "diagnose hardware get sysinfo df": "Filesystem Size Used Available Use% Mounted on\n/dev/a 10G 2G 8G 20% /\n",
        "get log setting local": "status: enable\nrotation-size: 100\ndisk-full: overwrite\n",
    }, {"diagnostic_recipes": ("disk_usage",)})
    answer = engine.fortios_diagnostics(auth, "disk_usage", "", "")
    assert answer["ok"], answer
    assert verify() == ["get system status", "diagnose hardware get sysinfo df", "get log setting local"]


def test_triage_slb(replay):
    from test_triage_slb import Device, POOL, VS, VS_STAT, SLB_LOAD, PERF

    install, verify = replay
    device = Device()
    answers = {f"show full-configuration {section}": body for section, body in device.configs.items()}
    answers.update({
        "get system performance": PERF,
        "diagnose server-load-balance slb_load": SLB_LOAD,
        f"diagnose server-load-balance vs_stat vdom root vs {VS}": VS_STAT,
    })
    auth = install("fortiadc", answers, {"config_access": ("read",), "adc_virtual_servers": (VS,),
                                        "adc_vdoms": ("root",), "adc_pools": (POOL,)})
    result = engine.triage_slb(auth, VS)
    assert result["ok"] and "slb_vs_stat" in result["checked"]
    commands = verify()
    assert f"diagnose server-load-balance vs_stat vdom root vs {VS}" in commands
    assert "diagnose server-load-balance slb_load" in commands
    assert f"show full-configuration load-balance virtual-server {VS}" in commands
    assert f"show full-configuration load-balance pool {POOL}" in commands


def test_missing_pin_refuses_before_starting_a_client(replay):
    install, _ = replay
    auth = install("fortinet", {})
    auth = replace(auth, host_key=None)
    result = engine.ssh_read(auth, "fortinet", "system_status", {}, 0, 16000)
    assert result["error_code"] == "host_key_mismatch"
    assert result["error"] == "missing Fortinet public host key; add host_key at enrollment"
    assert not list(engine._CONNECTION_LANES)


def test_fortiadc_config_uses_terminal_framing_and_stream_redaction(replay):
    from pathlib import Path
    from netops_helper.sanitize import digest_text

    install, verify = replay
    fixtures = Path(__file__).parent / "fixtures" / "fortiadc_adc_health"
    captured = (fixtures / "profile.out").read_text().splitlines(keepends=True)
    _, _, first = captured[0].partition("# ")
    body = first + "".join(captured[1:-1])
    command = "show full-configuration load-balance profile LB_PROF_TCP"
    auth = install("fortiadc", {command: body}, {"config_access": ("read",)})
    result = engine.config_read(auth, "fortiadc", "load-balance profile LB_PROF_TCP",
                                redaction="full", include_defaults=True)
    assert result["ok"] and result["capture_complete"]
    output = result["untrusted_device_output"]
    assert "set type tcp" in output
    assert result["content_sha256"] == digest_text(output)
    assert verify() == ["get system status", command]



def test_vdom_context_read_keeps_identity_and_verified_context_on_one_wire(replay):
    from test_fortios_multivdom import ROOT_STATUS, transcript

    install, verify = replay
    steps = transcript("512-A-root-arp")
    answers = {command: (answer, next_prompt) for (_, command, answer), (next_prompt, _, _) in zip(steps, steps[1:])}
    answers["get system status"] = ROOT_STATUS
    auth = install("fortinet", answers, {"diagnostic_vdoms": ("root",)}, prompt=steps[0][0])
    result = engine.ssh_read(auth, "fortinet", "arp_table", {}, 0, 16000)
    assert result["ok"] and result["vdom"] == "root" and result["vdom_index"] == 0
    assert "fortilink" in result["untrusted_device_output"]
    assert verify() == ["get system status", "config vdom", "edit root", "get system arp", "end"]



def test_fortiadc_interface_read_advances_pager_on_same_wire(replay):
    install, verify = replay
    command = "get system interface"
    auth = install("fortiadc", {command: ["== [ port1 ]\n", "== [ port2 ]\n"]})
    result = engine.ssh_read(auth, "fortiadc", "interface_list", None, 0, 16000)
    assert result["ok"] and result["untrusted_device_output"] == "== [ port1 ]\n== [ port2 ]\n"
    assert verify() == ["get system status", command]


def test_helper_preserves_output_after_a_delayed_prompt_line(replay):
    install, verify = replay
    command = "get system interface"
    auth = install("fortiadc", {command: {"tail": "== [ port2 ]\n"}})
    result = engine.ssh_read(auth, "fortiadc", "interface_list", None, 0, 16000)
    assert result["ok"] and "== [ port2 ]" in result["untrusted_device_output"], result
    assert verify() == ["get system status", command]


def test_fortios_cleanup_opens_a_single_repair_connection(replay):
    from test_fortios_diagnostics import INTERFACE, IP, Shell

    install, verify = replay
    model = Shell("ping")
    show = f'show full-configuration system interface "{INTERFACE}"'
    link = f"diagnose netlink interface list {INTERFACE}"
    view = "execute ping-options view-settings"
    restore = "execute ping-options repeat-count 5"
    select = "execute ping-options repeat-count 2"
    baseline = model.command(view)
    status = model.command("get system status")
    auth = install("fortinet", {"get system status": status, show: model.command(show), link: model.command(link),
                                view: baseline, select: None},
                   {"diagnostic_recipes": ("ping",), "addresses": (IP,), "interfaces": (INTERFACE,)},
                   repair={"get system status": status, view: baseline})
    result = engine.fortios_diagnostics(auth, "ping", IP, INTERFACE, count=2, timeout=1)
    assert (result["ok"], result["error_code"]) == (False, "disconnected")
    assert verify(2) == ["get system status", show, link, view, select, "get system status", restore, view]


def test_fortiadc_cleanup_opens_a_single_repair_connection(replay):
    from netops_helper.fortiadc_diagnostics import _state_filter

    install, verify = replay
    prefix = "diagnose server-load-balance session"
    show = f"{prefix} filter show"
    select = f"{prefix} filter 'vs-name VS_APP_HTTP'"
    baseline = "\n".join(f"{key}: {value}" for key, value in _state_filter("session", "0").items())
    auth = install("fortiadc", {show: baseline, select: None},
                   {"diagnostic_recipes": ("session_list",), "diagnostic_virtual_servers": ("VS_APP_HTTP",)},
                   repair={show: baseline})
    result = engine.fortios_diagnostics(auth, "session_list", "VS_APP_HTTP", "", timeout=1)
    assert (result["ok"], result["state"], result["cleanup"]) == (False, "incomplete", "verified"), result
    assert verify(2) == ["get system status", show, select, "get system status", f"{prefix} filter clear", show]


def test_vdom_navigation_disconnect_does_not_read_in_unverified_context(replay):
    from test_fortios_multivdom import ROOT_STATUS, transcript

    install, verify = replay
    auth = install("fortinet", {"get system status": ROOT_STATUS, "config vdom": None},
                   {"diagnostic_vdoms": ("root",)}, prompt=transcript("512-A-root-arp")[0][0])
    result = engine.ssh_read(auth, "fortinet", "arp_table", {}, 0, 16000)
    assert not result["ok"] and result["error_code"] == "disconnected"
    assert not result.get("untrusted_device_output")
    assert verify() == ["get system status", "config vdom"]


@pytest.mark.parametrize("recipe", ["disk_usage", "packet_capture"])
def test_fortiadc_diagnostic_disconnect_before_identity_closes_session(replay, recipe):
    from test_adc_objects_adc import INVENTORY, VS

    install, verify = replay
    inventory = {**INVENTORY, "diagnostic_recipes": (recipe,)}
    auth = install("fortiadc", {"get system status": None}, inventory)
    address, interface = (VS, "port2") if recipe == "packet_capture" else ("", "")
    result = engine.fortios_diagnostics(auth, recipe, address, interface)
    assert not result["ok"] and result["error_code"] == "disconnected"
    assert not result.get("untrusted_device_output") and engine._FORTINET_READER.get() is None
    assert verify() == ["get system status"]
