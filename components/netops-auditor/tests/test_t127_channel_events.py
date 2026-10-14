import json
import os
import sqlite3

import pytest

from netops_auditor import cli
from netops_auditor import collect
from netops_auditor.collect import SSH_STEPS, CollectError, collect_ssh
from netops_auditor import store as store_module

TENANT = "tenant-a"
DEVICE = "fw-example"
HOST = "198.51.100.10"
LOGIN = "audit-ro"
CREDENTIAL = "fw-example-audit-ro"
KEY_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIEdTwaiTIgcu/hVdAGf/B5Tu8i3/vYtTyb3SkSvXkYIi"
KEY_PIN = "SHA256:ainTqLVboX+ve469siLf72rOminn3mGxWCUt89zwYxc"
KEY = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nKANARCI-KLIC-T127\n-----END " + "OPENSSH PRIVATE KEY-----\n"
CONSOLE = b"output              : standard\n"
DUMP = 'config system global\n    set hostname "fw-example"\nend\n'
DEEP = "".join("config a%d\n" % level for level in range(70)) + "end\n" * 70
PREFLIGHT = "%s@%s %s" % (LOGIN, HOST, SSH_STEPS["fortios"][0].command)
SHOW = "%s@%s %s" % (LOGIN, HOST, SSH_STEPS["fortios"][1].command)


class Result:
    def __init__(self, returncode, stdout, stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Credential:
    kind = "ssh-key"
    login = LOGIN

    def use(self):
        return KEY


class Device:
    def __init__(self, show=DUMP, show_code=0):
        self.show = show.encode("utf-8")
        self.show_code = show_code
        self.sent = []

    def __call__(self, argv, **options):
        if argv[0] == "ssh-keyscan":
            return Result(0, ("%s ssh-ed25519 %s\n" % (HOST, KEY_BLOB)).encode("utf-8"))
        self.sent.append(argv[-1])
        if argv[-1] == SSH_STEPS["fortios"][0].command:
            return Result(0, CONSOLE)
        return Result(self.show_code, self.show)


def gather(device):
    return collect_ssh(DEVICE, "fortios", HOST, 22, Credential(), KEY_PIN, run=device, keyscan=device)


def trail(events):
    return [(event.request, event.outcome) for event in events]


def test_every_sent_command_stays_an_event_when_the_second_step_fails():
    _, events = gather(Device())
    assert trail(events) == [(PREFLIGHT, "ok"), (SHOW, "ok")]
    device = Device(show_code=1)
    with pytest.raises(CollectError) as caught:
        gather(device)
    assert device.sent == ["get system console", "show"]
    assert trail(caught.value.events) == [(PREFLIGHT, "ok"), (SHOW, "failed")]
    assert caught.value.event == caught.value.events[-1]


def test_a_refused_first_step_carries_only_its_own_event():
    device = Device()
    device_console = b"output              : more\n"

    def paged(argv, **options):
        answer = device(argv, **options)
        return Result(0, device_console) if argv[-1] == "get system console" else answer

    with pytest.raises(CollectError) as caught:
        gather(paged)
    assert device.sent == ["get system console"]
    assert trail(caught.value.events) == [(PREFLIGHT, "failed")]


def write_inventory(directory):
    path = directory / "inventory.json"
    path.write_text(json.dumps({"version": 2, "devices": [{
        "name": DEVICE, "platform": "fortios", "address": HOST, "port": 22, "role": "perimetr",
        "credential": CREDENTIAL, "host_key_fingerprint": KEY_PIN, "legacy_ssh": None,
        "auditor": {"channel": "ssh", "source": None, "required_sections": ["system global"],
                    "tls_fingerprint": None},
        "helper": None,
    }]}), encoding="utf-8")
    return path


def write_vault(directory):
    path = directory / "vault.json"
    path.write_text(json.dumps({"version": 2, "credentials": {
        CREDENTIAL: {"kind": "ssh-key", "login": LOGIN, "value": KEY}}}), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def collect_cli(capsys, monkeypatch, tmp_path, device, database):
    real = collect.collect_ssh

    def wired(*arguments, **named):
        return real(*arguments, run=device, keyscan=device, **named)

    monkeypatch.setattr(cli.collect, "collect_ssh", wired)
    code = cli.main([
        "collect", "--inventory", str(write_inventory(tmp_path)), "--vault", str(write_vault(tmp_path)),
        "--device", DEVICE, "--tenant", TENANT, "--store", str(database), "--json",
    ])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def stored(database):
    connection = sqlite3.connect(str(database))
    try:
        runs = connection.execute("SELECT id FROM runs ORDER BY id").fetchall()
        events = connection.execute(
            "SELECT request, outcome, run_id FROM channel_events ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    return [row[0] for row in runs], events


def status(capsys, database):
    code = cli.main(["status", "--tenant", TENANT, "--device", DEVICE, "--store", str(database), "--json"])
    return code, json.loads(capsys.readouterr().out)["state"]


def test_a_failed_second_step_records_the_first_command_too(tmp_path, capsys, monkeypatch):
    database = tmp_path / "audit.sqlite"
    code, out, err = collect_cli(capsys, monkeypatch, tmp_path, Device(show_code=1), database)
    assert code == cli.EXIT_ERROR
    assert out == ""
    assert "stayed unrecorded" not in err
    assert stored(database) == ([], [(PREFLIGHT, "ok", None), (SHOW, "failed", None)])


def test_a_run_refused_after_the_collection_keeps_the_events_of_the_collection(tmp_path, capsys, monkeypatch):
    database = tmp_path / "audit.sqlite"
    code, out, err = collect_cli(capsys, monkeypatch, tmp_path, Device(show=DUMP + DEEP), database)
    assert code == cli.EXIT_ERROR
    assert out == ""
    assert "nest deeper than" in err
    assert "stayed unrecorded" not in err
    assert stored(database) == ([], [(PREFLIGHT, "ok", None), (SHOW, "ok", None)])
    assert status(capsys, database) == (cli.EXIT_STALE, "never")


class Crash(BaseException):
    pass


def test_the_run_and_its_events_are_one_transaction(tmp_path, capsys, monkeypatch):
    database = tmp_path / "audit.sqlite"

    def crash(*arguments, **named):
        raise Crash()

    with monkeypatch.context() as patched:
        patched.setattr(store_module, "_checked_event", crash)
        with pytest.raises(Crash):
            collect_cli(capsys, patched, tmp_path, Device(), database)
    assert stored(database) == ([], [])
    assert status(capsys, database) == (cli.EXIT_STALE, "never")
    code, _, err = collect_cli(capsys, monkeypatch, tmp_path, Device(), database)
    assert (code, err) == (cli.EXIT_OK, "")
    runs, events = stored(database)
    assert len(runs) == 1
    assert events == [(PREFLIGHT, "ok", runs[0]), (SHOW, "ok", runs[0])]
    assert status(capsys, database) == (cli.EXIT_OK, "fresh")


def test_a_file_audit_still_records_no_channel_event(tmp_path, capsys):
    config = tmp_path / "device.conf"
    config.write_text(DUMP, encoding="utf-8")
    database = tmp_path / "audit.sqlite"
    code = cli.main(["run", "--platform", "fortios", "--tenant", TENANT, "--device", DEVICE,
                     "--config", str(config), "--store", str(database)])
    capsys.readouterr()
    assert code == cli.EXIT_OK
    runs, events = stored(database)
    assert len(runs) == 1 and events == []
