import json
import sqlite3

import pytest

from netops_auditor import cli, collect

TENANT = "tenant-a"
DEVICE = "fw-example"
INCOMPLETE_RULE = "fortios.snapshot.incomplete"
SECTIONS = ("system global", "system interface", "firewall policy")
HEAD = (
    "config system global\n"
    '    set hostname "fw-example"\n'
    "end\n"
    "config system interface\n"
    '    edit "port1"\n'
    "        set role lan\n"
    "        set allowaccess ping\n"
    "    next\n"
    "end\n"
)
POLICY = "config firewall policy\n    edit 1\n        set name \"x\"\n    next\nend\n"
INTERFACE_EDIT = 5
CUTS = (
    ("config system global\n    set", 1, 2),
    ("config system global\n    set ", 1, 2),
    (HEAD[: HEAD.index("        set role") + len("        set")], INTERFACE_EDIT, 1),
    (HEAD[: HEAD.index("        set allowaccess") + len("        set ")], INTERFACE_EDIT, 1),
)


def write_inventory(directory, config):
    path = directory / "inventory.json"
    path.write_text(json.dumps({"version": 2, "devices": [{
        "name": DEVICE, "platform": "fortios", "address": None, "port": None, "role": "perimetr",
        "credential": None, "host_key_fingerprint": None, "legacy_ssh": None,
        "auditor": {"channel": "file", "source": str(config), "required_sections": list(SECTIONS),
                    "tls_fingerprint": None},
        "helper": None,
    }]}), encoding="utf-8")
    return path


def collect_file(capsys, tmp_path, text, database, policy=None):
    config = tmp_path / "device.conf"
    config.write_text(text, encoding="utf-8")
    argv = ["collect", "--inventory", str(write_inventory(tmp_path, config)), "--device", DEVICE,
            "--tenant", TENANT, "--store", str(database), "--json"]
    if policy is not None:
        argv.extend(["--policy", str(policy)])
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def stored(database):
    connection = sqlite3.connect(str(database))
    try:
        runs = [row[0] for row in connection.execute("SELECT id FROM runs ORDER BY id")]
        events = connection.execute("SELECT outcome, run_id FROM channel_events ORDER BY id").fetchall()
    finally:
        connection.close()
    return runs, events


def status(capsys, database):
    code = cli.main(["status", "--tenant", TENANT, "--device", DEVICE, "--store", str(database), "--json"])
    return code, json.loads(capsys.readouterr().out)["state"]


def gate_of(out):
    report = json.loads(out)
    assert [item["rule_id"] for item in report["findings"]] == [INCOMPLETE_RULE]
    assert report["evaluation_complete"] is False
    return report["findings"][0]["evidence"]


def test_a_well_formed_dump_without_a_section_is_the_reference(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    code, out, err = collect_file(capsys, tmp_path, HEAD, database)
    assert (code, err) == (cli.EXIT_INCOMPLETE, "")
    assert gate_of(out) == {"missing_count": 1, "missing_sections": "firewall policy"}
    runs, events = stored(database)
    assert len(runs) == 1 and events == [("ok", runs[0])]


@pytest.mark.parametrize("text, line, missing", CUTS, ids=("global-set", "global-set-space", "edit-set", "edit-set-space"))
def test_a_dump_cut_inside_a_statement_is_an_incomplete_snapshot(tmp_path, capsys, text, line, missing):
    assert collect.unterminated_line(text, "fortios") == line
    database = tmp_path / "audit.sqlite"
    code, out, err = collect_file(capsys, tmp_path, text, database)
    assert (code, err) == (cli.EXIT_INCOMPLETE, "")
    evidence = gate_of(out)
    assert (evidence["missing_count"], evidence["unterminated_line"]) == (missing, line)
    runs, events = stored(database)
    assert len(runs) == 1 and events == [("ok", runs[0])]


def test_a_cut_dump_and_then_a_complete_one_are_two_runs_in_order(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    code, _, _ = collect_file(capsys, tmp_path, CUTS[2][0], database)
    assert code == cli.EXIT_INCOMPLETE
    assert status(capsys, database) == (cli.EXIT_STALE, "incomplete")
    code, out, err = collect_file(capsys, tmp_path, HEAD + POLICY, database)
    assert (code, err) == (cli.EXIT_OK, "")
    assert INCOMPLETE_RULE not in out
    runs, events = stored(database)
    assert events == [("ok", runs[0]), ("ok", runs[1])]
    assert status(capsys, database) == (cli.EXIT_OK, "fresh")


def test_a_mandatory_policy_rule_still_refuses_a_cut_dump_but_keeps_the_event(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "platform": "fortios", "required_rules": ["address-policy"]}))
    database = tmp_path / "audit.sqlite"
    code, out, err = collect_file(capsys, tmp_path, CUTS[2][0], database, policy=policy)
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert "mandatory policy rules not evaluated: address-policy" in err
    assert stored(database) == ([], [("ok", None)])


def test_a_complete_dump_with_a_broken_statement_is_still_refused(tmp_path, capsys):
    broken = HEAD.replace("        set role lan\n", "        set\n") + POLICY
    assert collect.unterminated_line(broken, "fortios") is None
    database = tmp_path / "audit.sqlite"
    code, out, err = collect_file(capsys, tmp_path, broken, database)
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert "cannot parse configuration" in err and "set without an attribute" in err
    assert stored(database) == ([], [("ok", None)])


def test_run_still_refuses_a_cut_file(tmp_path, capsys):
    config = tmp_path / "device.conf"
    config.write_text(CUTS[2][0], encoding="utf-8")
    code = cli.main(["run", "--platform", "fortios", "--tenant", TENANT, "--device", DEVICE,
                     "--config", str(config)])
    captured = capsys.readouterr()
    assert (code, captured.out) == (cli.EXIT_ERROR, "")
    assert "cannot parse configuration" in captured.err
