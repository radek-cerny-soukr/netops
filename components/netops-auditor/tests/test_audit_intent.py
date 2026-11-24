from datetime import datetime, timezone
import json

import pytest

from netops_auditor import engine, management
from test_multiplatform_collect import (
    Transport, install_catalog, invoke, payload, sample_hit,
)
from netops_auditor.collect import RUNNING


@pytest.mark.parametrize("invalid", [
    {"unknown": True}, {"external_aaa_required": 1}, {"syslog_severity": "unknown"},
    {"management_prefixes": ["192.0.2.5/24"]},
    {"ports": {"Ethernet1/1": {"native_vlan": 10}}},
    {"ports": {"Ethernet1/1": {"role": "trunk", "native_vlan": True}}},
    {"account_lockout_required": ["example"]},
])
def test_intent_is_strict(invalid):
    with pytest.raises(management.PolicyError):
        management.validate_intent(invalid, "cisco-ios")


def test_intent_only_keeps_history_when_visibility_changes(tmp_path, monkeypatch, capsys):
    def status(tree, context):
        visibility = context.visibility("snmp users")
        if visibility.state == "visible":
            return engine.EVALUATED, ""
        return engine.NOT_EVALUATED, visibility.reason

    rule = install_catalog(tmp_path, monkeypatch, "cisco-ios", sample_hit, status,
                           applies=lambda intent: intent.get("external_aaa_required", False))
    transport = Transport(RUNNING, payload("cisco_ios"))
    transport.install(monkeypatch)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"audit_intent": {"external_aaa_required": True}}))
    assert invoke(tmp_path, transport, extra=("--policy", str(policy), "--baseline-accept", "--accepted-by", "operator",
                                               "--note", "baseline")) == 0
    first = json.loads(capsys.readouterr().out)
    policy.write_text(json.dumps({"audit_intent": {"external_aaa_required": True, "ntp_auth_required": True}}))
    transport.answers["show snmp user"] = None
    assert invoke(tmp_path, transport, extra=("--policy", str(policy))) == 3
    second = json.loads(capsys.readouterr().out)
    assert first["rules_version"] == second["rules_version"]
    assert second["coverage"]["counts"]["not_evaluated"] == 1
    assert second["gone"] == []
    assert [item["rule_id"] for item in second["not_evaluated"]] == [rule]


def test_audit_intent_excluded_from_legacy_policy(tmp_path):
    path = tmp_path / "policy.json"
    baseline = {"platform": "fortios", "version": 1, "required_rules": ["address-policy"],
                "address_networks": ["192.0.2.0/24"]}
    path.write_text(json.dumps({**baseline, "audit_intent": {"external_aaa_required": True}}))
    policy, intent = management.load_audit_policy(path, "fortios")
    assert policy == baseline
    assert intent == {"external_aaa_required": True}
    assert management.policy_digest(policy) == management.policy_digest(baseline)


def test_live_partial_check_preserves_hidden_objects_and_cannot_accept_baseline(tmp_path, monkeypatch, capsys):
    from netops_auditor import query
    from netops_auditor.store import Store
    from test_channel_events_on_failure import DEVICE, TENANT

    def status(tree, context):
        answer = context.visibility("snmp users")
        return (engine.EVALUATED, "") if answer.state == "visible" else (engine.NOT_EVALUATED, answer.reason)

    def known_objects(tree, context):
        yield from sample_hit(tree, context)
        if context.visibility("snmp users").state == "visible":
            yield {"object_key": "supplemental", "section": "snmp users", "line": 1, "evidence": {"count": 1}}

    install_catalog(tmp_path, monkeypatch, "cisco-ios", known_objects, status, partial=True)
    transport = Transport(RUNNING, payload("cisco_ios"))
    transport.install(monkeypatch)
    assert invoke(tmp_path, transport) == 0
    capsys.readouterr()
    transport.answers["show snmp user"] = None
    assert invoke(tmp_path, transport) == 3
    report = json.loads(capsys.readouterr().out)
    assert [item["object_key"] for item in report["findings"]] == ["management"]
    assert [item["object_key"] for item in report["not_evaluated"]] == ["supplemental"]
    assert report["gone"] == []
    with Store(tmp_path / "audit.sqlite") as store:
        listing = query.list_findings(store, TENANT, DEVICE, now=datetime.now(timezone.utc))
        assert {item["object_key"]: item["state"] for item in listing["findings"]} == {
            "management": "new", "supplemental": "not-evaluated",
        }
        last, first = store.runs_for_device(TENANT, DEVICE)
        with pytest.raises(query.QueryError, match="unevaluated"):
            query.compare(store, TENANT, DEVICE, first["id"], last["id"])
    assert invoke(tmp_path, transport, extra=("--baseline-accept", "--accepted-by", "operator", "--note", "baseline")) == 2
    assert "cannot accept a baseline from an unevaluated audit" in capsys.readouterr().err
