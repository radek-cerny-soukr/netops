from __future__ import annotations

import json

from conftest import FIXTURES, request_bytes

from netops_admin.cli import EXIT_MISMATCH, EXIT_REJECTED, main


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
