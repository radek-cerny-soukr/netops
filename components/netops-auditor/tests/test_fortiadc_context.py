import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

import test_cli
from netops_auditor import cli, engine, mcp_server
from netops_auditor.engine import EVALUATED, NOT_EVALUATED, UNSUPPORTED, evaluate, load_catalog
from netops_auditor.l1_fortios import parse

FIXTURES = Path(__file__).parent / "fixtures" / "rules"
IDENTITY = {"platform": "FortiADC-KVM", "version": "7.6.7", "build": "0676"}
PREFIX = "fortiadc."
TRUSTED = PREFIX + "mgmt.trusted-hosts-open"
PLAIN = PREFIX + "mgmt.plaintext-admin-access"
TLS = PREFIX + "tls.legacy-versions"
FACTORY = PREFIX + "tls.factory-certificate"
NOHC = PREFIX + "lb.pool-no-health-check"
SINGLE = PREFIX + "lb.pool-single-member"
VERSION_GATE = PREFIX + "scope.unsupported-version"
VDOM_GATE = PREFIX + "scope.vdom-unsupported"
ALL_RULES = {TRUSTED, PLAIN, TLS, FACTORY, NOHC, SINGLE}

GOOD = (
    'config system admin\n    edit "admin"\n        set trusted-hosts 192.0.2.0/24\n    next\nend\n'
    'config system interface\n    edit "port1"\n        set allowaccess https ping ssh\n    next\nend\n'
    'config load-balance client-ssl-profile\n    edit "csp1"\n        set ssl-allowed-versions tlsv1.2 tlsv1.3\n    next\nend\n'
    'config load-balance pool\n    edit "pool1"\n        set health-check-ctrl enable\n'
    '        config pool_member\n            edit 1\n                set ip 192.0.2.10\n            next\n'
    '            edit 2\n                set ip 192.0.2.11\n            next\n        end\n    next\nend\n'
)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def meta(text, complete=True, limits=(), identity=None, digest=None):
    return {
        "version": 1,
        "sha256": digest or sha(text),
        "identity": dict(identity or IDENTITY),
        "configuration_complete": complete,
        "visibility_limitations": list(limits),
    }


def adc():
    from netops_auditor import checks_fortiadc
    return checks_fortiadc


def context(text, **keywords):
    return adc().build_context(meta(text, **keywords), sha(text))


def audit(text, ctx="auto", policy=None, **keywords):
    module = adc()
    if ctx == "auto":
        ctx = context(text, **keywords)
    return evaluate(parse(text), "t", "d", load_catalog("fortiadc"), module.attach(policy, ctx))


def states_of(states, wanted):
    return {rule for rule, (state, _reason) in states.items() if state == wanted}


def test_catalog_lists_gates_and_rules():
    assert {rule.id for rule in load_catalog("fortiadc")} == ALL_RULES | {VERSION_GATE, VDOM_GATE}


def test_complete_snapshot_with_explicit_safe_values_is_evaluated_clean():
    findings, states = audit(GOOD)
    assert findings == ()
    assert states_of(states, NOT_EVALUATED) == {FACTORY}
    assert states_of(states, EVALUATED) == (ALL_RULES - {FACTORY}) | {VERSION_GATE, VDOM_GATE}


def test_user_policy_cannot_supply_a_context():
    forged = {
        "sha256": sha(GOOD), "identity": tuple(IDENTITY.values()),
        "complete": True, "limitations": frozenset(),
    }
    for fake in (forged, SimpleNamespace(**forged), json.loads(json.dumps(forged, default=list))):
        findings, states = audit(GOOD, ctx=None, policy={adc().CONTEXT_KEY: fake})
        assert states_of(states, EVALUATED) == {VERSION_GATE, VDOM_GATE}
        assert states_of(states, UNSUPPORTED) == ALL_RULES
        assert {states[rule][1] for rule in ALL_RULES} == {VERSION_GATE}
        assert findings[0].rule_id == VERSION_GATE


def test_context_cannot_be_constructed_outside_the_loader():
    with pytest.raises(TypeError):
        adc().SnapshotContext(object(), sha(GOOD), tuple(IDENTITY.values()), True, frozenset())
    ctx = context(GOOD)
    with pytest.raises(AttributeError):
        ctx.complete = False


def test_attach_builds_a_new_object_and_never_mutates_the_shared_policy():
    module = adc()
    shared = {"required_rules": ["a"], module.CONTEXT_KEY: "from-user"}
    before = copy.deepcopy(shared)
    first_context, second_context = context(GOOD), context(GOOD + "\n")
    first = module.attach(shared, first_context)
    second = module.attach(shared, second_context)
    assert shared == before
    assert first is not shared and first is not second
    assert first[module.CONTEXT_KEY] is first_context
    assert second[module.CONTEXT_KEY] is second_context
    assert first["required_rules"] == ["a"]
    assert module.CONTEXT_KEY not in module.attach(shared, None)


def test_metadata_of_another_snapshot_is_refused():
    other = GOOD + "# other\n"
    with pytest.raises(adc().ContextError):
        adc().build_context(meta(other), sha(GOOD))
    with pytest.raises(adc().ContextError):
        adc().build_context(meta(GOOD, digest="0" * 64), sha(GOOD))


def test_second_snapshot_does_not_inherit_the_context_of_the_first():
    first, _ = audit(GOOD)
    second_text = GOOD.replace("tlsv1.2 tlsv1.3", "tlsv1.0")
    findings, states = audit(second_text, ctx=None)
    assert first == () and findings[0].rule_id == VERSION_GATE
    assert states_of(states, UNSUPPORTED) == ALL_RULES
    again, states = audit(second_text)
    assert [item.rule_id for item in again] == [TLS]


@pytest.mark.parametrize("bad", [
    {"complete": True, "limits": ["networking"]},
    {"complete": False, "limits": []},
    {"complete": False, "limits": ["nonsense"]},
    {"complete": False, "limits": ["user", "user"]},
])
def test_contradictory_or_unknown_metadata_is_refused(bad):
    with pytest.raises(adc().ContextError):
        adc().build_context(meta(GOOD, complete=bad["complete"], limits=bad["limits"]), sha(GOOD))


@pytest.mark.parametrize("identity", [
    {"platform": "FortiADC-KVM", "version": "7.6.6", "build": "0676"},
    {"platform": "FortiADC-KVM", "version": "7.6.7", "build": "0675"},
    {"platform": "FortiADC-VM", "version": "7.6.7", "build": "0676"},
])
def test_any_other_identity_makes_everything_unsupported(identity):
    findings, states = audit(GOOD, identity=identity)
    assert [item.rule_id for item in findings] == [VERSION_GATE]
    assert states_of(states, UNSUPPORTED) == ALL_RULES


def test_vdom_scope_is_a_gate():
    text = GOOD + 'config system vdom\n    edit "a"\n    next\n    edit "b"\n    next\nend\n'
    findings, states = audit(text)
    assert [item.rule_id for item in findings] == [VDOM_GATE]
    assert states_of(states, UNSUPPORTED) == ALL_RULES
    findings, _ = audit(GOOD, complete=False, limits=["vdom-override-unverified"])
    assert [item.rule_id for item in findings] == [VDOM_GATE]


@pytest.mark.parametrize("rule,old,new", [
    (TRUSTED, "set trusted-hosts 192.0.2.0/24\n", ""),
    (TRUSTED, "192.0.2.0/24", "<REDACTED:credential#1>"),
    (PLAIN, "set allowaccess https ping ssh\n", ""),
    (PLAIN, "https ping ssh", "<UNVERIFIED:unsupported-format>"),
    (TLS, "set ssl-allowed-versions tlsv1.2 tlsv1.3\n", ""),
    (TLS, "tlsv1.2 tlsv1.3", "<UNVERIFIED:unclassified-field>"),
    (NOHC, "set health-check-ctrl enable\n", ""),
    (NOHC, "health-check-ctrl enable", "health-check-ctrl <REDACTED>"),
])
def test_missing_default_or_marked_value_is_not_evaluated_never_clean(rule, old, new):
    assert GOOD.count(old) == 1
    findings, states = audit(GOOD.replace(old, new))
    assert findings == ()
    assert states[rule][0] == NOT_EVALUATED and states[rule][1]
    others = ALL_RULES - {rule, FACTORY}
    assert all(states[name][0] == EVALUATED for name in others)


def test_absent_admin_or_interface_section_is_not_evaluated():
    text = GOOD[GOOD.index("config load-balance client-ssl-profile"):]
    _, states = audit(text)
    assert states[TRUSTED][0] == NOT_EVALUATED and states[PLAIN][0] == NOT_EVALUATED
    assert states[TLS][0] == EVALUATED


def test_incomplete_area_blocks_clean_but_unrelated_limitation_does_not():
    _, states = audit(GOOD, complete=False, limits=["networking"])
    assert states[PLAIN][0] == NOT_EVALUATED and states[PLAIN][1] == "visibility:networking"
    assert states[TRUSTED][0] == EVALUATED and states[SINGLE][0] == EVALUATED
    _, states = audit(GOOD, complete=False, limits=["user"])
    assert states_of(states, NOT_EVALUATED) == {FACTORY}
    _, states = audit(GOOD, complete=False, limits=["access-profile-unverified"])
    assert states_of(states, NOT_EVALUATED) == ALL_RULES


def test_visible_risk_is_reported_even_when_a_global_limitation_exists():
    text = GOOD.replace("192.0.2.0/24", "0.0.0.0/0")
    findings, states = audit(text, complete=False, limits=["access-profile-unverified"])
    assert [item.rule_id for item in findings] == [TRUSTED]
    assert states[TRUSTED][0] == EVALUATED
    assert states[TLS][0] == NOT_EVALUATED


@pytest.mark.parametrize("rule,old,new,evidence", [
    (TRUSTED, "192.0.2.0/24", "::/0", {"admin": "admin", "trusted_hosts": "::/0"}),
    (TRUSTED, "192.0.2.0/24", "0.0.0.0 0.0.0.0", {"admin": "admin", "trusted_hosts": "0.0.0.0 0.0.0.0"}),
    (PLAIN, "https ping ssh", "https telnet", {"interface": "port1", "service": "telnet"}),
    (TLS, "tlsv1.2 tlsv1.3", "tlsv1.1 tlsv1.2", {"profile": "csp1", "versions": "tlsv1.1"}),
    (NOHC, "health-check-ctrl enable", "health-check-ctrl disable", {"pool": "pool1"}),
    (SINGLE, "            edit 2\n                set ip 192.0.2.11\n            next\n", "", {"pool": "pool1"}),
])
def test_explicit_risky_values_are_findings(rule, old, new, evidence):
    assert GOOD.count(old) == 1
    findings, states = audit(GOOD.replace(old, new))
    assert [item.rule_id for item in findings] == [rule]
    assert dict(findings[0].evidence) == evidence
    assert states[rule][0] == EVALUATED


@pytest.mark.parametrize("name", ["default", "Fortinet_Factory", "my-cert"])
def test_certificate_group_name_without_provenance_is_never_a_finding(name):
    text = GOOD.replace("tlsv1.2 tlsv1.3\n", "tlsv1.2 tlsv1.3\n        set local-cert-group %s\n" % name)
    findings, states = audit(text)
    assert findings == ()
    assert states[FACTORY][0] == NOT_EVALUATED
    assert states[FACTORY][1].startswith("factory-provenance-unproven:csp1=" + name)
    assert states_of(states, EVALUATED) >= ALL_RULES - {FACTORY}


def test_certificate_rule_without_binding_is_still_not_evaluated():
    _, states = audit(GOOD)
    assert states[FACTORY] == (NOT_EVALUATED, "factory-provenance-unproven")


@pytest.mark.parametrize("rule", sorted(ALL_RULES - {FACTORY}))
def test_catalog_fixtures_positive_finds_negative_is_quiet(rule):
    positive = (FIXTURES / rule / "positive.conf").read_text()
    negative = (FIXTURES / rule / "negative.conf").read_text()
    assert rule in {item.rule_id for item in audit(positive)[0]}
    assert rule not in {item.rule_id for item in audit(negative)[0]}


@pytest.mark.parametrize("gate", [VERSION_GATE, VDOM_GATE])
def test_gate_fixtures(gate):
    positive = (FIXTURES / gate / "positive.conf").read_text()
    negative = (FIXTURES / gate / "negative.conf").read_text()
    if gate == VERSION_GATE:
        assert [i.rule_id for i in audit(positive, identity={**IDENTITY, "build": "1"})[0]] == [gate]
        assert [i.rule_id for i in audit(negative)[0]] == []
    else:
        assert [i.rule_id for i in audit(positive)[0]] == [gate]
        assert [i.rule_id for i in audit(negative)[0]] == []


def test_engine_run_is_status_aware():
    probe_name, check_name = "status_probe_check", "status_probe_hidden"
    engine._CHECKS[check_name] = lambda tree: iter(({"object_key": "k", "section": "s", "line": 1, "evidence": {}},))
    engine._STATUS[check_name] = lambda tree, policy=None: (NOT_EVALUATED, "no-data")
    rule = engine.Rule("status.hidden", 1, check_name, "fakt", "low", (), "t", "r", (), "")
    try:
        assert engine.run(parse(""), "t", "d", (rule,)) == ()
        findings, states = evaluate(parse(""), "t", "d", (rule,))
        assert findings == () and states["status.hidden"] == (NOT_EVALUATED, "no-data")
    finally:
        engine._CHECKS.pop(check_name)
        engine._STATUS.pop(check_name)


def test_engine_run_with_adc_context_matches_evaluate():
    module = adc()
    text = GOOD.replace("192.0.2.0/24", "0.0.0.0/0").replace("set ssl-allowed-versions tlsv1.2 tlsv1.3\n", "")
    rules = load_catalog("fortiadc")
    policy = module.attach(None, context(text))
    assert engine.run(parse(text), "t", "d", rules, policy) == evaluate(parse(text), "t", "d", rules, policy)[0]
    assert [i.rule_id for i in engine.run(parse(text), "t", "d", rules, policy)] == [TRUSTED]
    assert [i.rule_id for i in engine.run(parse(text), "t", "d", rules)] == [VERSION_GATE]


def cli_run(capsys, tmp_path, text, meta_document=None, extra=()):
    config = test_cli.write_config(tmp_path, text)
    argv = test_cli.run_args(config, as_json=True, platform="fortiadc", device="adc-example")
    if meta_document is not None:
        path = tmp_path / "meta.json"
        path.write_text(json.dumps(meta_document))
        argv += ["--snapshot-meta", str(path)]
    code, out, err = test_cli.invoke(capsys, argv + list(extra))
    return code, (json.loads(out) if out else None), err


def test_cli_clean_complete_snapshot_exits_ok_and_shows_not_evaluated_certificate_rule(capsys, tmp_path):
    code, report, _ = cli_run(capsys, tmp_path, GOOD, meta(GOOD))
    assert code == cli.EXIT_OK
    assert report["findings"] == []
    assert report["rule_status"][FACTORY]["status"] == NOT_EVALUATED
    assert report["rule_status"][TLS]["status"] == EVALUATED
    assert report["evaluation_complete"] is False


def test_cli_marked_value_is_visible_as_not_evaluated(capsys, tmp_path):
    text = GOOD.replace("192.0.2.0/24", "<REDACTED:credential#1>")
    code, report, _ = cli_run(capsys, tmp_path, text, meta(text))
    assert code == cli.EXIT_INCOMPLETE
    assert report["findings"] == []
    assert report["rule_status"][TRUSTED]["status"] == NOT_EVALUATED
    assert report["rule_status"][TRUSTED]["reason"] == "redacted-or-unverified-value"
    assert report["evaluation_complete"] is False


def test_cli_without_metadata_is_unsupported_not_clean(capsys, tmp_path):
    code, report, _ = cli_run(capsys, tmp_path, GOOD)
    assert code == cli.EXIT_INCOMPLETE
    assert [item["rule_id"] for item in report["findings"]] == [VERSION_GATE]
    assert {report["rule_status"][rule]["status"] for rule in ALL_RULES} == {UNSUPPORTED}


def test_cli_metadata_of_another_snapshot_is_an_error(capsys, tmp_path):
    code, report, err = cli_run(capsys, tmp_path, GOOD, meta(GOOD + "# x\n"))
    assert code == cli.EXIT_ERROR and report is None
    assert "another snapshot" in err


def test_cli_second_run_does_not_reuse_the_metadata_of_the_first(capsys, tmp_path):
    first, _, _ = cli_run(capsys, tmp_path, GOOD, meta(GOOD))
    second_dir = tmp_path / "second"
    second_dir.mkdir()
    code, report, _ = cli_run(capsys, second_dir, GOOD.replace("tlsv1.3", "tlsv1.1"))
    assert [item["rule_id"] for item in report["findings"]] == [VERSION_GATE]


def test_cli_policy_file_cannot_carry_completeness(capsys, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "platform": "fortiadc", adc().CONTEXT_KEY: {"complete": True}}))
    code, report, err = cli_run(capsys, tmp_path, GOOD, meta(GOOD), extra=["--policy", str(policy)])
    assert code == cli.EXIT_ERROR and report is None
    assert "policy" in err


def test_cli_snapshot_meta_is_refused_for_other_platforms(capsys, tmp_path):
    config = test_cli.write_config(tmp_path, "config system global\nend\n")
    path = tmp_path / "meta.json"
    path.write_text("{}")
    argv = test_cli.run_args(config, platform="fortios") + ["--snapshot-meta", str(path)]
    code, _, err = test_cli.invoke(capsys, argv)
    assert code == cli.EXIT_ERROR and "fortiadc" in err


def test_api_lists_fortiadc_catalog():
    assert "fortiadc" in mcp_server.available_platforms()
    assert {rule.id for rule in mcp_server._rules("fortiadc")} == ALL_RULES | {VERSION_GATE, VDOM_GATE}


HELPER_META = {
    "firmware": {"model": "FortiADC-KVM", "version": "7.6.7", "build": "0676"},
    "config_scope": "all", "configuration_complete": True, "visibility_limitations": [],
    "unverified_count": 0, "unsupported_format_count": 0,
}


def helper_meta(**changes):
    document = dict(HELPER_META)
    document["firmware"] = dict(HELPER_META["firmware"])
    firmware = {key: changes.pop(key) for key in ("model", "version", "build") if key in changes}
    document["firmware"].update(firmware)
    document.update(changes)
    return {key: value for key, value in document.items() if value is not None}


def test_helper_metadata_converts_to_the_auditor_form():
    converted = adc().from_helper_metadata(helper_meta(), sha(GOOD))
    assert converted == meta(GOOD)
    ctx = adc().build_context(converted, sha(GOOD))
    findings, states = audit(GOOD, ctx=ctx)
    assert findings == ()
    assert states_of(states, UNSUPPORTED) == set()


def test_helper_visibility_limitations_pass_through_and_block_clean():
    converted = adc().from_helper_metadata(
        helper_meta(configuration_complete=False, visibility_limitations=["networking"]), sha(GOOD))
    assert converted["visibility_limitations"] == ["networking"]
    _findings, states = audit(GOOD, ctx=adc().build_context(converted, sha(GOOD)))
    assert states[PLAIN] == (NOT_EVALUATED, "visibility:networking")


@pytest.mark.parametrize("changes", [
    {"build": "0700"}, {"version": "7.6.8"}, {"version": "8.0.2"}, {"model": "FortiGate-60F"},
])
def test_helper_metadata_of_another_build_is_never_a_supported_snapshot(changes):
    converted = adc().from_helper_metadata(helper_meta(**changes), sha(GOOD))
    findings, states = audit(GOOD, ctx=adc().build_context(converted, sha(GOOD)))
    assert findings[0].rule_id == VERSION_GATE
    assert states_of(states, UNSUPPORTED) == ALL_RULES


@pytest.mark.parametrize("changes", [
    {"firmware": None}, {"configuration_complete": None}, {"visibility_limitations": None},
    {"configuration_complete": "yes"}, {"version": 7}, {"firmware": {"model": "FortiADC-KVM"}},
    {"configuration_complete": True, "visibility_limitations": ["system"]},
    {"configuration_complete": False, "visibility_limitations": []},
])
def test_malformed_helper_metadata_is_refused(changes):
    with pytest.raises(adc().ContextError):
        adc().build_context(adc().from_helper_metadata(helper_meta(**changes), sha(GOOD)), sha(GOOD))


@pytest.mark.parametrize("key", ["content_sha256", "snapshot_sha256"])
def test_helper_metadata_of_another_text_is_refused(key):
    with pytest.raises(adc().ContextError, match="another snapshot"):
        adc().from_helper_metadata(helper_meta(**{key: sha(GOOD + "# x\n")}), sha(GOOD))
    assert adc().from_helper_metadata(helper_meta(**{key: sha(GOOD)}), sha(GOOD)) == meta(GOOD)


def test_cli_accepts_the_metadata_document_written_by_the_helper(capsys, tmp_path):
    code, report, _ = cli_run(capsys, tmp_path, GOOD, helper_meta())
    assert code == cli.EXIT_OK
    assert report["findings"] == []
    assert report["rule_status"][TLS]["status"] == EVALUATED
    assert report["rule_status"][FACTORY]["status"] == NOT_EVALUATED


def test_cli_helper_metadata_of_another_build_reports_the_version_gate(capsys, tmp_path):
    code, report, _ = cli_run(capsys, tmp_path, GOOD, helper_meta(build="0700"))
    assert [item["rule_id"] for item in report["findings"]] == [VERSION_GATE]
    assert {report["rule_status"][rule]["status"] for rule in ALL_RULES} == {UNSUPPORTED}


@pytest.mark.parametrize('output', ['json', 'sarif'])
@pytest.mark.parametrize('scenario', ['inherent', 'user', 'networking', 'actionable', 'version'])
def test_cli_process_coverage(tmp_path, output, scenario):
    text = GOOD
    if scenario == 'actionable':
        text = text.replace('set trusted-hosts 192.0.2.0/24\n', '')
    identity = dict(IDENTITY)
    if scenario == 'version':
        identity['version'] = '7.6.6'
    config = tmp_path / 'snapshot.conf'
    config.write_text(text)
    metadata = tmp_path / 'meta.json'
    limits = [scenario] if scenario in ('networking', 'user') else []
    metadata.write_text(json.dumps(meta(text, complete=not limits, limits=limits, identity=identity)))
    args = [sys.executable, '-B', '-m', 'netops_auditor.cli', 'run', '--platform', 'fortiadc',
            '--tenant', 't', '--device', 'd', '--config', str(config), '--snapshot-meta', str(metadata), '--' + output]
    result = subprocess.run(args, capture_output=True, text=True, env=os.environ.copy())
    assert result.returncode == (0 if scenario in ('inherent', 'user') else 3), result.stderr
    report = json.loads(result.stdout)
    if output == 'sarif':
        report = report['runs'][0]['properties']['devices'][0]
    assert report['evaluation_complete'] is False
    coverage = report['coverage']
    assert coverage['complete'] is False
    if scenario in ('inherent', 'user'):
        assert {gap['rule_id'] for gap in coverage['inherent_gaps']} == {FACTORY}
        assert coverage['actionable_gaps'] == []
    elif scenario == 'networking':
        assert {gap['rule_id'] for gap in coverage['inherent_gaps']} == {FACTORY}
        assert {(gap['rule_id'], gap['reason']) for gap in coverage['actionable_gaps']} == {(PLAIN, 'visibility:networking')}
    else:
        assert coverage['actionable_gaps']


@pytest.mark.parametrize('limits', [[], ['networking']])
def test_status_reports_the_coverage_of_the_last_run(capsys, tmp_path, limits):
    store = tmp_path / 'audit.sqlite'
    config = test_cli.write_config(tmp_path, GOOD)
    metadata = tmp_path / 'meta.json'
    metadata.write_text(json.dumps(meta(GOOD, complete=not limits, limits=limits)))
    argv = test_cli.run_args(config, as_json=True, store=store, platform='fortiadc', device='adc-example')
    code, _out, _err = test_cli.invoke(capsys, argv + ['--snapshot-meta', str(metadata)])
    assert code == (cli.EXIT_INCOMPLETE if limits else cli.EXIT_OK)
    code, out, _err = test_cli.invoke(capsys, test_cli.status_args(store, device='adc-example', as_json=True))
    report = json.loads(out)
    # status keeps the conservative reading: any gap, inherent or not, is "incomplete".
    assert code == cli.EXIT_STALE and report['state'] == 'incomplete'
    assert report['coverage']['complete'] is False
    assert {gap['rule_id'] for gap in report['coverage']['inherent_gaps']} == {FACTORY}
    assert bool(report['coverage']['actionable_gaps']) is bool(limits)


def test_status_of_a_device_without_a_run_has_no_coverage(capsys, tmp_path):
    store = tmp_path / 'audit.sqlite'
    test_cli.seed_run(store, test_cli.moment(1), device='other')
    code, out, _err = test_cli.invoke(capsys, test_cli.status_args(store, device='adc-example', as_json=True))
    assert json.loads(out)['coverage'] is None


@pytest.mark.parametrize("limits", [[], ["networking"]])
def test_text_run_and_status_show_coverage(capsys, tmp_path, limits):
    store = tmp_path / "audit.sqlite"
    config = test_cli.write_config(tmp_path, GOOD)
    metadata = tmp_path / "meta.json"
    metadata.write_text(json.dumps(meta(GOOD, complete=not limits, limits=limits)))
    argv = test_cli.run_args(config, store=store, platform="fortiadc", device="adc-example")
    code, run, _ = test_cli.invoke(capsys, argv + ["--snapshot-meta", str(metadata)])
    assert code == (cli.EXIT_INCOMPLETE if limits else cli.EXIT_OK)
    code, status, _ = test_cli.invoke(capsys, test_cli.status_args(store, device="adc-example"))
    assert code == cli.EXIT_STALE
    for output in (run, status):
        assert "coverage complete: false" in output
        assert "coverage inherent_gaps: 1\n  %s: factory-provenance-unproven" % FACTORY in output
        assert "coverage actionable_gaps: %d" % bool(limits) in output
        if limits:
            assert "  %s: visibility:networking" % PLAIN in output


def test_text_status_without_run_shows_unavailable_coverage(capsys, tmp_path):
    store = tmp_path / "audit.sqlite"
    test_cli.seed_run(store, test_cli.moment(1), device="other")
    _, output, _ = test_cli.invoke(capsys, test_cli.status_args(store, device="adc-example"))
    assert "coverage: unavailable" in output
