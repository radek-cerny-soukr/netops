"""Replay a FortiOS snapshot through actual fake OpenSSH processes.

The router section comes from the FortiOS 7.6.8 capture documented in
netops-admin/tests/fixtures/fortios_7_6_8_net/README.md. The remaining snapshot
sections, console values and terminal framing are derived test inputs.
"""

import hashlib
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops_auditor import cli, collect, fortios_audit
from netops_core.session import fortinet_session
from test_channel_events_on_failure import (
    CONSOLE, DEVICE, DUMP, HOST, IDENTITY, KEY_BLOB, KEY_PIN, PREFLIGHT, SHOW, STATUS, TENANT, Credential,
    targeted, write_inventory, write_vault,
)


ROUTES = Path(__file__).resolve().parents[2] / (
    "netops-admin/tests/fixtures/fortios_7_6_8_net/show-router-static__baseline.txt"
)
PUBLIC_KEY = "ssh-ed25519 " + KEY_BLOB
FAKE_CLIENT = r"""
from pathlib import Path
import sys
import tty

def record(value):
    with open(LOG, "a") as log:
        log.write(value + "\n")

program = Path(sys.argv[0]).name
record(program)
if program == "ssh-keyscan":
    sys.stdout.write(KEY_LINE + "\n")
    sys.exit(0)

assert "StrictHostKeyChecking=yes" in sys.argv
assert "ControlMaster=no" in sys.argv and "ControlPath=none" in sys.argv
path = Path(next(arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("UserKnownHostsFile=")))
assert path.read_text() == KEY_LINE + "\n"

def answer(command):
    record("command: " + command)
    return ANSWERS[command]

if "-tt" not in sys.argv:
    sys.stdout.buffer.write(answer(sys.argv[-1]))
    sys.exit(0)

tty.setraw(0)
prompt = b"FortiGate-60F # "
sys.stdout.buffer.write(b"login banner\r\n" + prompt)
sys.stdout.buffer.flush()
for line in sys.stdin.buffer:
    command = line.rstrip(b"\n")
    if not command:
        sys.stdout.buffer.write(b"\r\r\n" + prompt)
        sys.stdout.buffer.flush()
        continue
    body = answer(command.decode())
    if body is None:
        sys.stderr.write("device words CANARY-FORTIOS-SSH\n")
        sys.exit(255)
    if command == b"show" and ANSWERS["get system console"].endswith(b": more\n"):
        first, _, tail = body.partition(b"\n")
        sys.stdout.buffer.write(command + b"\r\r\n" + first + b"\r\n--Mo")
        sys.stdout.buffer.flush()
        import time
        time.sleep(0.005)
        sys.stdout.buffer.write(b"re--")
        sys.stdout.buffer.flush()
        assert sys.stdin.buffer.read(1) == b" "
        sys.stdout.buffer.write(b"\r         \r" + tail.replace(b"\n", b"\r\n") + prompt)
        sys.stdout.buffer.flush()
        continue
    sys.stdout.buffer.write(command + b"\r\r\n" + body.replace(b"\n", b"\r\n") + prompt)
    sys.stdout.buffer.flush()
"""


def _fake_client(tmp_path, monkeypatch, console, snapshot):
    log = tmp_path / "client.log"
    answers = {"get system status": IDENTITY, "get system console": console, "show": snapshot}
    answers.update({step.command: targeted(snapshot or b"", step.command)
                    for step in fortios_audit.SSH_STEPS if step.command not in answers})
    script = (
        f"#!{sys.executable}\nLOG = {str(log)!r}\nKEY_LINE = {f'{HOST} {PUBLIC_KEY}'!r}\n"
        f"ANSWERS = {answers!r}\n" + FAKE_CLIENT
    )
    for name in ("ssh", "ssh-keyscan"):
        client = tmp_path / name
        client.write_text(script)
        client.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))
    return log


def _cli_collect(tmp_path, *, host_key):
    inv = write_inventory(tmp_path)
    if host_key is not None:
        inventory = json.loads(inv.read_text())
        inventory["devices"][0]["host_key"] = host_key
        inv.write_text(json.dumps(inventory))
    database = tmp_path / "audit.sqlite"
    code = cli.main([
        "collect", "--inventory", str(inv), "--vault", str(write_vault(tmp_path)),
        "--device", DEVICE, "--tenant", TENANT, "--store", str(database), "--json",
    ])
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(
            "SELECT request, outcome, response_sha256, response_bytes FROM channel_events ORDER BY id"
        ).fetchall()
    return code, rows


def _event(request, outcome, response):
    return request, outcome, hashlib.sha256(response).hexdigest(), len(response)


@pytest.mark.parametrize("standard", (True, False), ids=("standard", "more"))
def test_collect_starts_one_ssh_and_no_scan(tmp_path, monkeypatch, capsys, standard):
    console = CONSOLE if standard else CONSOLE.replace(b": standard", b": more")
    routes = ROUTES.read_bytes()
    start = routes.index(b"config router static\n")
    end = routes.index(b"\nend\n", start) + len(b"\nend\n")
    snapshot = DUMP.encode() + routes[start:end]
    log = _fake_client(tmp_path, monkeypatch, console, snapshot)
    code, actual_rows = _cli_collect(tmp_path, host_key=PUBLIC_KEY)
    out, err = capsys.readouterr()
    assert (code, err) == (cli.EXIT_OK, "")
    assert json.loads(out)["collection"]["snapshot_sha256"] == hashlib.sha256(snapshot).hexdigest()
    assert actual_rows[:3] == [
        _event(STATUS, "ok", IDENTITY),
        _event(PREFLIGHT, "ok", console),
        _event(SHOW, "ok", snapshot),
    ]
    assert len(actual_rows) == len(fortios_audit.SSH_STEPS)
    assert log.read_text().splitlines() == ["ssh", *[
        "command: " + step.command for step in fortios_audit.SSH_STEPS
    ]]


def test_missing_inventory_key_is_refused_before_starting_a_client(tmp_path, monkeypatch, capsys):
    log = _fake_client(tmp_path, monkeypatch, CONSOLE, b"")
    code, rows = _cli_collect(tmp_path, host_key=None)
    out, err = capsys.readouterr()
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert "add host_key at enrollment" in err
    assert rows == [_event(STATUS, "failed", b"")]
    assert not log.exists()


def test_disconnect_on_show_preserves_the_preflight_event(tmp_path, monkeypatch, capsys):
    log = _fake_client(tmp_path, monkeypatch, CONSOLE, None)
    code, rows = _cli_collect(tmp_path, host_key=PUBLIC_KEY)
    out, err = capsys.readouterr()
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert "disconnected before a prompt" in err
    assert "CANARY-FORTIOS-SSH" not in err
    assert rows == [_event(STATUS, "ok", IDENTITY), _event(PREFLIGHT, "ok", CONSOLE), _event(SHOW, "failed", b"")]
    assert log.read_text().splitlines() == ["ssh", "command: get system status", "command: get system console", "command: show"]


@pytest.mark.parametrize("standard", (True, False), ids=("standard", "more"))
def test_collection_leaves_the_borrowed_session_open(tmp_path, monkeypatch, standard):
    console = CONSOLE if standard else CONSOLE.replace(b": standard", b": more")
    log = _fake_client(tmp_path, monkeypatch, console, DUMP.encode())
    target = SimpleNamespace(platform="fortios", address=HOST, port=22,
                             host_key_fingerprint=KEY_PIN, host_key=PUBLIC_KEY)
    credential = Credential()
    commands = ["command: " + step.command for step in fortios_audit.SSH_STEPS]
    with fortinet_session(target, credential) as opened:
        args = DEVICE, target.platform, HOST, 22, credential, KEY_PIN
        snapshot, events = collect.collect_ssh(*args, session=opened)
        assert snapshot.text == DUMP
        assert [event.outcome for event in events] == ["ok"] * len(commands)
        assert opened.run("get system console").stdout == console
        commands.append("command: get system console")
    assert log.read_text().splitlines() == ["ssh", *commands]
