import json
from datetime import datetime, timezone

from netops_auditor import cli, query
from netops_auditor.store import Store

TENANT = "tenant-a"
DEVICE = "fw-example"
RULE = "fortios.management.group-empty"
GLOBAL = 'config system global\n    set hostname "fw-example"\nend\n'
ADDRESS = 'config firewall address\n    edit "h1"\n        set subnet 192.0.2.1 255.255.255.255\n    next\nend\n'
EMPTY_GROUP = GLOBAL + ADDRESS + 'config firewall addrgrp\n    edit "g1"\n    next\nend\n'
NO_GROUPS = GLOBAL
FILLED_GROUP = GLOBAL + ADDRESS + 'config firewall addrgrp\n    edit "g1"\n        set member "h1"\n    next\nend\n'


def audit(capsys, tmp_path, database, text):
    config = tmp_path / "device.conf"
    config.write_text(text, encoding="utf-8")
    code = cli.main(["run", "--platform", "fortios", "--tenant", TENANT, "--device", DEVICE,
                     "--config", str(config), "--store", str(database), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_OK
    return {
        "complete": report["evaluation_complete"],
        "status": report["rule_status"][RULE]["status"],
        "present": [item["state"] for item in report["findings"] if item["rule_id"] == RULE],
        "gone": [item["rule_id"] for item in report["gone"] if item["rule_id"] == RULE],
        "not_evaluated": [item["rule_id"] for item in report.get("not_evaluated", []) if item["rule_id"] == RULE],
    }


def listed(database):
    with Store(database) as store:
        answer = query.list_findings(store, TENANT, DEVICE, now=datetime.now(timezone.utc))
    return [item["state"] for item in answer["findings"] + answer["gone"] if item["rule_id"] == RULE]


def test_an_advisory_finding_is_gone_when_the_next_audit_no_longer_reports_it(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    first = audit(capsys, tmp_path, database, EMPTY_GROUP)
    assert (first["status"], first["present"]) == ("evaluated", ["new"])
    resolved = audit(capsys, tmp_path, database, FILLED_GROUP)
    assert (resolved["present"], resolved["gone"]) == ([], [RULE])
    assert audit(capsys, tmp_path, database, FILLED_GROUP)["gone"] == []


def test_an_advisory_finding_survives_an_audit_that_did_not_evaluate_its_rule(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    audit(capsys, tmp_path, database, EMPTY_GROUP)
    skipped = audit(capsys, tmp_path, database, NO_GROUPS)
    assert (skipped["complete"], skipped["status"]) == (True, "not-evaluated")
    assert (skipped["gone"], skipped["not_evaluated"]) == ([], [RULE])
    resolved = audit(capsys, tmp_path, database, FILLED_GROUP)
    assert resolved["status"] == "evaluated" and resolved["present"] == []
    assert (resolved["gone"], resolved["not_evaluated"]) == ([RULE], [])
    assert audit(capsys, tmp_path, database, FILLED_GROUP)["gone"] == []


def test_an_advisory_finding_is_carried_across_several_audits_that_skip_its_rule(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    audit(capsys, tmp_path, database, EMPTY_GROUP)
    for _ in range(3):
        skipped = audit(capsys, tmp_path, database, NO_GROUPS)
        assert (skipped["gone"], skipped["not_evaluated"]) == ([], [RULE])
        assert listed(database) == ["not-evaluated"]
    reported = audit(capsys, tmp_path, database, EMPTY_GROUP)
    assert (reported["present"], reported["gone"], reported["not_evaluated"]) == (["new"], [], [])
    assert listed(database) == ["new"]
    audit(capsys, tmp_path, database, NO_GROUPS)
    resolved = audit(capsys, tmp_path, database, FILLED_GROUP)
    assert (resolved["gone"], resolved["not_evaluated"]) == ([RULE], [])
    assert listed(database) == ["gone"]
