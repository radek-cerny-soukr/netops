from __future__ import annotations

import json

import pytest
from conftest import FIXTURES, request_bytes

from netops_admin.cli import (EXIT_CONFIRMED_BLOCKED, EXIT_MISMATCH, EXIT_NOT_CONFIRMED, EXIT_NOT_READY,
                              EXIT_REJECTED, main)


def run(capsys, *argv):
    code = main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_plan_and_verify_round_trip(tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_bytes(request_bytes(op="update", key="spare-host", changes={"comment": "reserved"}))
    snapshot = str(FIXTURES / "fortios_8_0_0.conf")
    code, document = run(capsys, "plan", "--platform", "fortios", "--snapshot", snapshot,
                         "--request", str(request))
    assert code == 0
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(document), encoding="utf-8")
    code, result = run(capsys, "verify", "--plan", str(plan), "--snapshot", snapshot, "--expect", "before")
    assert (code, result["result"]) == (0, "match")
    code, result = run(capsys, "verify", "--plan", str(plan), "--snapshot", snapshot)
    assert (code, result["result"]) == (EXIT_MISMATCH, "mismatch")
    assert result["differences"] == ["comment: expected 'reserved', found 'unused'"]


def test_rejection_is_reported_with_its_own_exit_code(tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_bytes(request_bytes(op="delete", key="srv-web", changes={}))
    code, document = run(capsys, "plan", "--platform", "fortios",
                         "--snapshot", str(FIXTURES / "fortios_8_0_0.conf"), "--request", str(request))
    assert code == EXIT_REJECTED
    assert document["result"] == "rejected"
    assert "is referenced" in document["reasons"][0]


def test_policy_file_is_strict(tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_bytes(request_bytes())
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"protected": {"firewall address": ["x"]}, "allow_all": True}), encoding="utf-8")
    code, document = run(capsys, "plan", "--platform", "fortios", "--snapshot",
                         str(FIXTURES / "fortios_8_0_0.conf"), "--request", str(request), "--policy", str(policy))
    assert code == EXIT_REJECTED
    assert "policy may hold only" in document["reasons"][0]


def test_missing_snapshot_is_a_rejection(tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_bytes(request_bytes())
    code, document = run(capsys, "plan", "--platform", "fortios", "--snapshot", str(tmp_path / "absent.conf"),
                         "--request", str(request))
    assert code == EXIT_REJECTED
    assert "cannot be read" in document["reasons"][0]


def operate(monkeypatch, tmp_path, capsys, record, *command):
    from netops_admin import cli, config, execute

    monkeypatch.setattr(config, "load_config", lambda _path: None)
    monkeypatch.setattr(cli, "build_runtime", lambda _config: None)
    monkeypatch.setattr(execute, "apply", lambda _runtime, _device, _request: record)
    monkeypatch.setattr(execute, "undo", lambda _runtime, _change_id, _reason: record)
    request = tmp_path / "request.json"
    request.write_bytes(request_bytes())
    arguments = {"apply": ("--device", "fw", "--request", str(request)),
                 "undo": ("--change-id", "c1", "--reason", "back")}[command[0]]
    return run(capsys, command[0], "--config", str(tmp_path / "admin.json"), *arguments)


@pytest.mark.parametrize("command", ["apply", "undo"])
@pytest.mark.parametrize("reason", ["not persisted", "foreign change during save", "saved configuration unverified"])
def test_confirmed_change_that_blocked_the_device_has_its_own_exit_code(monkeypatch, tmp_path, capsys, command, reason):
    code, document = operate(monkeypatch, tmp_path, capsys, {"result": "confirmed", "reason": reason}, command)
    assert (code, document["result"], document["reason"]) == (EXIT_CONFIRMED_BLOCKED, "confirmed", reason)
    assert EXIT_CONFIRMED_BLOCKED not in (0, EXIT_MISMATCH, 2, EXIT_REJECTED, EXIT_NOT_CONFIRMED, EXIT_NOT_READY)


@pytest.mark.parametrize("record, expected", [
    ({"result": "confirmed", "reason": None}, 0),
    ({"result": "reverted", "reason": "foreign change"}, EXIT_NOT_CONFIRMED),
    ({"result": "unknown", "reason": "foreign change after the safeguard was removed"}, EXIT_NOT_CONFIRMED),
])
def test_other_results_keep_their_exit_codes(monkeypatch, tmp_path, capsys, record, expected):
    code, _document = operate(monkeypatch, tmp_path, capsys, record, "apply")
    assert code == expected


@pytest.mark.parametrize("settled, expected", [
    ([], 0),
    ([{"result": "reverted", "reason": "interrupted"}], 0),
    ([{"result": "rejected", "reason": "interrupted before any mutation"}], 0),
    ([{"result": "reverted", "reason": "foreign change"}], EXIT_CONFIRMED_BLOCKED),
    ([{"result": "reverted", "reason": "interrupted"}, {"result": "unknown", "reason": "interrupted; state unreadable"}],
     EXIT_CONFIRMED_BLOCKED),
])
def test_recover_exits_with_the_blocked_code_when_a_settled_operation_blocked_the_device(
        monkeypatch, tmp_path, capsys, settled, expected):
    from netops_admin import cli, config, execute

    monkeypatch.setattr(config, "load_config", lambda _path: None)
    monkeypatch.setattr(cli, "build_runtime", lambda _config: None)
    monkeypatch.setattr(execute, "recover", lambda _runtime, _device: settled)
    code, document = run(capsys, "recover", "--config", str(tmp_path / "admin.json"), "--device", "sw")
    assert (code, document["settled"]) == (expected, settled)


def test_failed_save_on_the_switch_exits_with_the_blocked_code(monkeypatch, tmp_path, capsys):
    from fake_exos import FakeExos
    from test_execute_exos import make_runtime

    from netops_admin import cli, config

    device = FakeExos()
    device.refuse_save = True
    runtime = make_runtime(tmp_path, device)
    monkeypatch.setattr(config, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "build_runtime", lambda _config: runtime)
    request = tmp_path / "request.json"
    request.write_bytes(request_bytes(table="vlan", key="guest", changes={"tag": 3999, "description": "guest wifi"}))
    code, document = run(capsys, "apply", "--config", str(tmp_path / "admin.json"), "--device", "sw",
                         "--request", str(request))
    assert (code, document["result"], document["reason"]) == (EXIT_CONFIRMED_BLOCKED, "confirmed", "not persisted")
    assert runtime.store.blocked("sw")["reason"] == "not persisted"
