import json
import os
import re
import sqlite3
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from netops_auditor import cli
from netops_auditor import collect
from netops_auditor.collect import CollectError, collect_ssh
from netops_auditor.fortios_audit import SSH_STEPS
from netops_auditor import store as store_module
from test_cli import complete

TENANT = "tenant-a"
DEVICE = "fw-example"
HOST = "198.51.100.10"
LOGIN = "audit-ro"
CREDENTIAL = "fw-example-audit-ro"
KEY_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIEdTwaiTIgcu/hVdAGf/B5Tu8i3/vYtTyb3SkSvXkYIi"
KEY_PIN = "SHA256:ainTqLVboX+ve469siLf72rOminn3mGxWCUt89zwYxc"
KEY = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nCANARY-KEY-CHANNEL-EVENTS\n-----END " + "OPENSSH PRIVATE KEY-----\n"
CONSOLE = b"output              : standard\n"
DUMP = complete('config system global\n    set hostname "fw-example"\nend\nconfig system admin\n    edit "netadmin"\n        set accprofile "super_admin"\n        set trusthost1 192.0.2.0 255.255.255.0\n        set ip6-trusthost1 2001:db8::/32\n    next\nend\n')
DEEP = "".join("config a%d\n" % level for level in range(70)) + "end\n" * 70
STATUS, PREFLIGHT, SHOW = (f"{LOGIN}@{HOST} {name}" for name in (
    "get system status", "get system console", "show",
))
REQUESTS = tuple(f"{LOGIN}@{HOST} {step.command}" for step in SSH_STEPS)
IDENTITY = b"Version: FortiGate v7.6.8\n"



class Credential:
    kind = "ssh-key"
    login = LOGIN

    def use(self):
        return KEY


class Device:
    def __init__(self, show=DUMP, show_code=0, console=CONSOLE):
        self.show = show.encode("utf-8")
        self.show_code = show_code
        self.console = console
        self.sent = []

    def run(self, command, **options):
        self.sent.append(command)
        if command == "get system console":
            return SimpleNamespace(rc=0, stdout=self.console, stderr=b"")
        if command == "get system status":
            return SimpleNamespace(rc=0, stdout=IDENTITY, stderr=b"")
        if command == "show":
            return SimpleNamespace(rc=self.show_code, stdout=self.show, stderr=b"")
        return SimpleNamespace(rc=0, stdout=targeted(self.show, command), stderr=b"")


def targeted(body, command):
    section = command.removeprefix("show ").removeprefix("full-configuration ").encode()
    match = re.search(rb"^config " + re.escape(section) + rb"\n.*?^end\n", body, re.M | re.S)
    block = match[0] if match else b""
    if not command.startswith("show full-configuration "):
        return block

    # Scalar readbacks in FortiOS's full rendering include default fields.
    defaults = {
        b"system global": (b"admin-ssh-v1 disable",),
        b"system snmp sysinfo": (b"status disable",),
        b"system ntp": (b"ntpsync enable", b"type fortiguard", b"authentication disable"),
    }
    for suffix in (b"", b"2", b"3", b"4"):
        defaults[b"log syslogd" + suffix + b" setting"] = (b"status disable",)
        defaults[b"log syslogd" + suffix + b" filter"] = (b"severity information",)
    if section in defaults:
        if not block:
            block = b"config " + section + b"\nend\n"
        fields = b"".join(
            b"    set " + item + b"\n" for item in defaults[section]
            if b"\n    set " + item.split()[0] + b" " not in block
        )
        block = block[:-4] + fields + b"end\n"
    return block



def gather(device):
    return collect_ssh(DEVICE, "fortios", HOST, 22, Credential(), KEY_PIN, session=device)


def trail(events):
    return [(event.request, event.outcome) for event in events]


def test_every_sent_command_stays_an_event_when_the_primary_step_fails():
    _, events = gather(Device())
    assert trail(events) == [(request, "ok") for request in REQUESTS]
    device = Device(show_code=1)
    with pytest.raises(CollectError) as caught:
        gather(device)
    assert device.sent == ["get system status", "get system console", "show"]
    assert trail(caught.value.events) == [(STATUS, "ok"), (PREFLIGHT, "ok"), (SHOW, "failed")]
    assert caught.value.event == caught.value.events[-1]


def test_a_refused_console_diagnostic_does_not_block_the_snapshot():
    device = Device(console=b"Permission denied\n")
    snapshot, events = gather(device)
    assert snapshot.text == DUMP
    assert trail(events)[:3] == [(STATUS, "ok"), (PREFLIGHT, "failed"), (SHOW, "ok")]
    assert device.sent == [step.command for step in SSH_STEPS]



def write_inventory(directory):
    path = directory / "inventory.json"
    path.write_text(json.dumps({"version": 2, "devices": [{
        "name": DEVICE, "platform": "fortios", "address": HOST, "port": 22, "role": "perimeter",
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
    monkeypatch.setattr(collect, "fortinet_session", lambda *args, **kwargs: nullcontext(device))
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
    assert stored(database) == ([], [(STATUS, "ok", None), (PREFLIGHT, "ok", None), (SHOW, "failed", None)])


def test_a_run_refused_after_the_collection_keeps_the_events_of_the_collection(tmp_path, capsys, monkeypatch):
    database = tmp_path / "audit.sqlite"
    code, out, err = collect_cli(capsys, monkeypatch, tmp_path, Device(show=DUMP + DEEP), database)
    assert code == cli.EXIT_ERROR
    assert out == ""
    assert "nest deeper than" in err
    assert "stayed unrecorded" not in err
    assert stored(database) == ([], [(request, "ok", None) for request in REQUESTS])
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
    assert events == [(request, "ok", runs[0]) for request in REQUESTS]
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


def test_registered_fortios_collector_can_add_auxiliary_evidence(monkeypatch):
    from netops_auditor import platforms

    def metadata(snapshot, answers, visibility):
        return platforms.SnapshotMetadata("fortios", visibility, answers, complete=True)

    steps = (
        platforms.SSHStep("get system status", section="identity"),
        platforms.SSHStep("show", snapshot=True, prompt=True),
        platforms.SSHStep("show full-configuration system admin", section="system admin"),
    )
    module = SimpleNamespace(SSH_STEPS=steps, snapshot_metadata=metadata)
    monkeypatch.setattr(collect.platforms, "optional_collector", lambda key: module)

    class Profile(Device):
        def run(self, command, **options):
            if command == "show":
                return super().run(command, **options)
            self.sent.append(command)
            return SimpleNamespace(rc=0, stdout=b"" if "full-configuration" in command else b"version\n", stderr=b"")

    profile = Profile()
    snapshot, events = gather(profile)
    assert profile.sent == [step.command for step in steps]
    assert [event.outcome for event in events] == ["ok", "ok", "ok"]
    assert snapshot.metadata.auxiliary["system admin"] == ""
    assert snapshot.metadata.visibility("identity").state == "visible"
