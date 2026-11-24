"""What the plan_sha256 of the deprecated FortiADC commands pool-member, pool-member-add and pool-member-remove binds,
and that their --preview runs the HA write check before it reports `ready`.

Real path: cli.main -> fortiadc.run / fortiadc_member.add / remove over a fake transport answering with the targeted
FortiADC captures of the pool member and HA fixtures (prompt and pager cleaned as the SSH layer does)."""
import dataclasses
import json

import pytest

from netops_admin import cli, config, fortiadc
from test_fortiadc_adc_ha_state import PRIMARY_DOWN, SECONDARY
from test_fortiadc_adc_pool_members import POOL, TARGET
from test_fortiadc_member_cli_plan_required import COMMANDS, bench


def run(capsys, argv):
    code = cli.main(argv)
    return code, json.loads(capsys.readouterr().out)


def second_target(monkeypatch, **fields):
    """A second configured FortiADC that answers exactly like the first (same host name and pool state)."""
    configured = config.load_config("unused")
    devices = dict(configured.devices)
    devices["adc-b"] = dataclasses.replace(devices["adc"], name="adc-b", **fields)
    other = dataclasses.replace(configured, devices=devices)
    monkeypatch.setattr(config, "load_config", lambda _path: other)


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("fields", [
    {"address": "192.0.2.41", "host_key_fingerprint": "SHA256:" + "B" * 43},
    {"host_key_fingerprint": "SHA256:" + "B" * 43},
    {"address": "192.0.2.41"},
    {},
], ids=["address-and-key", "key", "address", "alias"])
def test_a_hash_approved_for_one_target_is_refused_on_another(tmp_path, monkeypatch, capsys, command, fields):
    wire, opened, argv, _write = bench(tmp_path, monkeypatch, command)
    second_target(monkeypatch, **fields)
    code, preview = run(capsys, argv + ["--preview"])
    assert (code, preview["result"]) == (0, "ready"), preview
    other = [value if value != "adc" else "adc-b" for value in argv]
    code, other_preview = run(capsys, other + ["--preview"])
    assert (code, other_preview["result"]) == (0, "ready"), other_preview
    assert other_preview["plan_sha256"] != preview["plan_sha256"]
    code, document = run(capsys, other + ["--expect-plan-sha256", preview["plan_sha256"]])
    assert (code, document["result"], document["reason_codes"]) == (cli.EXIT_REJECTED, "rejected", ["plan_changed"])
    assert wire.writes == []


def test_pool_member_hash_binds_the_backend_of_the_member(tmp_path, monkeypatch, capsys):
    wire, opened, argv, _write = bench(tmp_path, monkeypatch, "pool-member")
    code, preview = run(capsys, argv + ["--preview"])
    assert (code, preview["result"]) == (0, "ready"), preview
    listing = fortiadc.show_command(POOL)
    swapped = wire.answers[listing].replace("set real-server %s" % TARGET, "set real-server RS_A")
    assert swapped != wire.answers[listing]
    wire.answers[listing] = swapped
    # Same member number and status, the checks still pass: only the backend changed.
    code, again = run(capsys, argv + ["--preview"])
    assert (code, again["result"], again["before"]) == (0, "ready", preview["before"])
    assert again["plan_sha256"] != preview["plan_sha256"]
    code, document = run(capsys, argv + ["--expect-plan-sha256", preview["plan_sha256"]])
    assert (code, document["result"], document["reason_codes"]) == (cli.EXIT_REJECTED, "rejected", ["plan_changed"])
    assert wire.writes == []


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize(("ha", "code"), [(SECONDARY, "fortiadc_ha_secondary"),
                                          (PRIMARY_DOWN, "fortiadc_ha_not_synchronized")],
                         ids=["secondary", "primary-not-synchronized"])
def test_preview_on_an_unwritable_ha_member_is_refused(tmp_path, monkeypatch, capsys, command, ha, code):
    wire, opened, argv, _write = bench(tmp_path, monkeypatch, command)
    wire.answers[fortiadc.HA_STATUS] = ha
    exit_code, preview = run(capsys, argv + ["--preview"])
    assert (exit_code, preview["result"], preview["reason_codes"]) == (cli.EXIT_REJECTED, "rejected", [code])
    assert "plan_sha256" not in preview
    assert ("write-read", fortiadc.HA_STATUS) in wire.trace
    assert wire.writes == [] and not any(kind == "write" for kind, _ in wire.trace)
