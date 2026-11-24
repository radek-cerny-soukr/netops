"""The deprecated FortiADC CLI commands pool-member, pool-member-add and pool-member-remove write only with the
plan_sha256 of their own approved --preview, like every Admin apply.

Real path: cli.main -> fortiadc.run / fortiadc_member.add / remove over a fake transport answering with the
targeted FortiADC captures of the pool member fixtures (same answers as the HA post-write tests)."""
import json
import re

import pytest

from netops_admin import cli, config, fortiadc, fortiadc_member
from netops_core import prompt
from test_fortiadc_adc_ha_state import PRIMARY_SYNC, PairWire
from test_fortiadc_adc_pool_members import POOL, RS, TARGET, capture
from test_fortiadc_admin_runtime import make_runtime
from fake_fortiadc_admin import measured

COMMANDS = ["pool-member", "pool-member-add", "pool-member-remove"]


def answer(text):
    return prompt.cleaned(fortiadc.PAGER.sub("", text), "fortiadc")


def bench(tmp_path, monkeypatch, command):
    listing = fortiadc.show_command(POOL)
    base = answer(measured("show_load-balance_pool_LAB_POOL_SMTP.txt"))
    added = answer(capture("pool-member-before"))
    if command == "pool-member":
        before, changed = added, added.replace("set status disable", "set status maintain")
        write = fortiadc.render(POOL, "13", "maintain")
        flags = ["--status", "maintain"]
    elif command == "pool-member-add":
        before, changed = base, added
        write = fortiadc_member.render_add(POOL, "13", TARGET, "2525")
        flags = ["--real-server", TARGET, "--service-port", "2525"]
    else:
        before, changed = added, base
        write = fortiadc_member.render_remove(POOL, "13")
        flags = []
    wire = PairWire([write], before={fortiadc.HA_STATUS: PRIMARY_SYNC, listing: before,
                                     "show " + RS: answer(capture("real-ip")),
                                     fortiadc.VS_COMMAND: answer(capture("vs-smtp-baseline"))},
                    after={fortiadc.HA_STATUS: PRIMARY_SYNC, listing: changed})
    runtime = make_runtime(tmp_path, wire, certified=False)
    opened = []

    def open_access(device):
        opened.append(device.name)
        return wire

    monkeypatch.setattr(config, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "open_access", open_access)
    monkeypatch.setattr(fortiadc, "sleep", lambda _seconds: None, raising=False)
    argv = [command, "--config", "unused", "--device", "adc", "--pool", POOL, "--member", "13", *flags]
    return wire, opened, argv, write


def run(capsys, argv):
    code = cli.main(argv)
    return code, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("command", COMMANDS)
def test_without_the_preview_hash_nothing_is_read_or_written(tmp_path, monkeypatch, capsys, command):
    wire, opened, argv, _write = bench(tmp_path, monkeypatch, command)
    code, document = run(capsys, argv)
    assert (code, document["result"], document["reason_codes"]) == (cli.EXIT_REJECTED, "rejected", ["plan_changed"])
    assert "--preview" in document["reasons"][0]
    assert opened == [] and wire.trace == [] and wire.writes == []


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("value", ["A" * 64, "a" * 10, "z" * 64])
def test_a_malformed_hash_is_refused_before_the_device_is_contacted(tmp_path, monkeypatch, capsys, command, value):
    wire, opened, argv, _write = bench(tmp_path, monkeypatch, command)
    code, document = run(capsys, argv + ["--expect-plan-sha256", value])
    assert (code, document["result"]) == (cli.EXIT_REJECTED, "rejected")
    assert "64 lowercase hexadecimal" in document["reasons"][0]
    assert opened == [] and wire.trace == [] and wire.writes == []


@pytest.mark.parametrize("command", COMMANDS)
def test_preview_writes_nothing_and_its_hash_approves_the_write(tmp_path, monkeypatch, capsys, command):
    wire, opened, argv, write = bench(tmp_path, monkeypatch, command)
    code, preview = run(capsys, argv + ["--preview"])
    assert (code, preview["result"]) == (0, "ready"), preview
    assert re.fullmatch("[0-9a-f]{64}", preview["plan_sha256"])
    assert preview["preview"]["commands"] == write
    assert wire.writes == [] and not any(kind == "write" for kind, _ in wire.trace)
    assert wire.answers == wire.original
    code, applied = run(capsys, argv + ["--expect-plan-sha256", preview["plan_sha256"]])
    assert (code, applied["result"]) == (0, "confirmed"), applied
    assert applied["plan_sha256"] == preview["plan_sha256"]
    assert wire.writes == [write]


@pytest.mark.parametrize("command", COMMANDS)
def test_a_hash_no_preview_of_this_state_issued_is_plan_changed_without_write(tmp_path, monkeypatch, capsys, command):
    wire, opened, argv, _write = bench(tmp_path, monkeypatch, command)
    code, preview = run(capsys, argv + ["--preview"])
    assert preview["result"] == "ready"
    other = "0" * 64 if preview["plan_sha256"] != "0" * 64 else "1" * 64
    code, document = run(capsys, argv + ["--expect-plan-sha256", other])
    assert (code, document["result"], document["reason_codes"]) == (cli.EXIT_REJECTED, "rejected", ["plan_changed"])
    assert document["reason_details"] == [{"code": "plan_changed", "expected": other,
                                           "actual": preview["plan_sha256"]}]
    assert wire.writes == []


def test_the_hash_binds_the_state_the_preview_read(tmp_path, monkeypatch, capsys):
    # pool-member-remove: the member's settings are part of the plan (its inverse recreates them)
    wire, opened, argv, _write = bench(tmp_path, monkeypatch, "pool-member-remove")
    code, preview = run(capsys, argv + ["--preview"])
    assert preview["result"] == "ready"
    listing = fortiadc.show_command(POOL)
    changed = wire.answers[listing].replace("set status disable", "set status maintain")
    assert changed != wire.answers[listing]
    wire.answers[listing] = changed
    code, document = run(capsys, argv + ["--expect-plan-sha256", preview["plan_sha256"]])
    assert (code, document["result"], document["reason_codes"]) == (cli.EXIT_REJECTED, "rejected", ["plan_changed"])
    assert wire.writes == []
