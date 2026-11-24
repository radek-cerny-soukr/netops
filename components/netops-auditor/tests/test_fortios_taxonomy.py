import json

import pytest

from netops_auditor import cli, engine, l1_fortios, platforms
from test_cli import (
    DEVICE, TENANT, TLS_FINGERPRINT, audit, clean_text, gather, rest_item, write_config, write_inventory, write_vault,
)
from test_collect import FakeOpener
from test_fortios_ro_visibility import FIXTURES, collect_replay, table


CASES = (
    ("mgmt.ssh-v1", {}, "system interface", "permission-denied"),
    ("aaa.external-login", {"external_aaa_required": True}, "system admin", "admin-visibility-unproven"),
    ("snmp.v3-auth-priv", {}, "system snmp user", "permission-denied"),
    ("time.ntp-auth", {"ntp_auth_required": True}, "system ntp", "permission-denied"),
    ("logging.syslog-level", {"syslog_severity": "notice"}, "log syslogd2 filter", "permission-denied"),
    ("ports.unused-up", {"ports": {"port-a": {"role": "unused"}}}, "system interface", "permission-denied"),
)


def evaluate(rule, tree, intent, metadata=None):
    context = platforms.AuditContext(intent, metadata, live=metadata is not None)
    findings, states = engine.evaluate(tree, "example", "firewall", (rule,), context=context)
    return findings, states[rule.id]


@pytest.mark.parametrize("suffix,intent,section,reason", CASES, ids=[case[0] for case in CASES])
def test_rule_fixture_triplet(suffix, intent, section, reason):
    rule = next(rule for rule in engine.load_catalog("fortios") if rule.id == "fortios." + suffix)
    fixtures = FIXTURES / "rules" / rule.id
    for name in ("positive", "negative"):
        tree = l1_fortios.parse((fixtures / f"{name}.conf").read_text())
        findings, state = evaluate(rule, tree, intent)
        assert state == (engine.EVALUATED, "")
        assert len(findings) == (name == "positive")
        if intent:
            assert evaluate(rule, tree, {}) == ((), (engine.EVALUATED, ""))

    partial = (fixtures / "not-evaluated.conf").read_text()
    if section == "system admin":
        responses = {f"show full-configuration {section}": partial}
    else:
        # An enrolled full profile proves that this gap comes from the
        # requested section, while permissions for other sections are intact.
        partial += (FIXTURES / "rules" / "fortios.aaa.external-login" / "positive.conf").read_text()
        responses = {f"show full-configuration {section}": "Permission denied\n"}
    snapshot, _ = collect_replay(partial, responses)
    hits, state = evaluate(rule, snapshot.metadata.tree, intent, snapshot.metadata)
    assert not hits
    assert state == (engine.NOT_EVALUATED, reason)


def test_enforced_ntp_auth_reports_only_key_presence():
    rule = next(rule for rule in engine.load_catalog("fortios") if rule.id == "fortios.time.ntp-auth")
    root = FIXTURES / "rules" / rule.id
    intent = {"ntp_auth_required": True}
    text = (root / "negative.conf").read_text()
    masked = text.replace("REDACTED", "NTP-SECRET-CANARY")
    assert evaluate(rule, l1_fortios.parse(masked), intent)[0] == ()
    missing = text.replace('set key "REDACTED"', 'unset key')
    findings, state = evaluate(rule, l1_fortios.parse(missing), intent)
    assert state == (engine.EVALUATED, "")
    assert dict(findings[0].evidence) == {"issue": "key-missing"}
    assert "ntp.example.invalid" not in repr(findings)
    assert evaluate(rule, l1_fortios.parse("config system ntp\nset ntpsync enable\nset type fortiguard\nend\n"),
                    intent) == ((), (engine.EVALUATED, ""))


@pytest.mark.parametrize("channel", ("file", "fortios-rest"))
@pytest.mark.parametrize("case", ("clean", "no-v3-users", "v2c", "weak-v3", "auth-priv", "ssh-v1"))
def test_default_elided_snapshot(tmp_path, capsys, monkeypatch, channel, case):
    text = clean_text()
    rule_id = "fortios.snmp.v3-auth-priv"
    if case in ("no-v3-users", "v2c", "weak-v3", "auth-priv"):
        text += "config system snmp sysinfo\n    set status enable\nend\n"
    if case == "v2c":
        community = (FIXTURES / "rules/fortios.snmp.v1v2c-community/positive.conf").read_text()
        text += table(community, "system snmp community")
    if case == "weak-v3":
        text += 'config system snmp user\n    edit "monitor"\n    next\nend\n'
    if case == "auth-priv":
        text += 'config system snmp user\n    edit "monitor"\n        set security-level auth-priv\n    next\nend\n'
    if case == "ssh-v1":
        rule_id = "fortios.mgmt.ssh-v1"
        text = text.replace('    set hostname "fw-example"\n',
                            '    set hostname "fw-example"\n    set admin-ssh-v1 enable\n')

    has_finding = case in ("weak-v3", "ssh-v1")
    if channel == "file":
        code, out, err = audit(capsys, write_config(tmp_path, text), as_json=True)
        assert code == cli.EXIT_OK
    else:
        opener = FakeOpener(fingerprint=TLS_FINGERPRINT, body=text.encode())
        monkeypatch.setattr(cli.collect, "_open", opener)
        database = tmp_path / "audit.sqlite"
        code, out, err = gather(capsys, write_inventory(tmp_path, [rest_item()]), as_json=True,
                                vault_path=write_vault(tmp_path), store=database)
        assert opener.targets() == (cli.collect.REST_TARGET,)
        assert code == cli.EXIT_OK
        status_code = cli.main(["status", "--tenant", TENANT, "--device", DEVICE,
                                "--store", str(database), "--json"])
        assert status_code == cli.EXIT_OK
        assert json.loads(capsys.readouterr().out)["state"] == "fresh"
    assert not err
    report = json.loads(out)
    for rule in ("fortios.mgmt.ssh-v1", "fortios.snmp.v3-auth-priv"):
        assert report["rule_status"][rule]["status"] == "evaluated"
    found = {finding["rule_id"] for finding in report["findings"]}
    assert (rule_id in found) == has_finding
    if case == "v2c":
        assert "fortios.snmp.v1v2c-community" in found
