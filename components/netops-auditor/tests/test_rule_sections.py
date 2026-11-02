import json
import re
import shutil
from pathlib import Path

import pytest

from netops_auditor import cli, engine, l1_exos, l1_fortios, management
from netops_auditor.engine import NOT_EVALUATED, CatalogError, evaluate, load_catalog, section_missing
from test_cli import complete, invoke, run_args, write_config

RULE_FIXTURES = Path(__file__).parent / "fixtures" / "rules"
REAL_SECTIONS = Path(__file__).parent / "fixtures" / "real-sections"
REAL_DEVICES = ("fortigate-60f-7.6.8", "fortigate-80f-8.0.2")
PARSERS = {"fortios": l1_fortios, "exos": l1_exos}
MODULE = re.compile(r"^# Module (\S+) configuration\.$")
CASES = tuple(
    (platform, rule)
    for platform in sorted(PARSERS)
    for rule in load_catalog(platform)
    if not rule.scope_gate
)
IDS = tuple(rule.id for _platform, rule in CASES)


def blocks(platform, text):
    lines = text.splitlines(keepends=True)
    found = {}
    if platform == "fortios":
        start = name = None
        for index, line in enumerate(lines):
            if start is None and line.startswith("config "):
                start, name = index, line[len("config "):].strip()
            elif start is not None and line.rstrip("\r\n") == "end":
                found.setdefault(name, []).append((start, index + 1))
                start = None
        return lines, found
    starts = []
    for index, line in enumerate(lines):
        header = MODULE.match(line.rstrip("\r\n"))
        if header is not None:
            begin = index - 1 if index and lines[index - 1].rstrip("\r\n") == "#" else index
            starts.append((begin, header.group(1)))
    for position, (begin, name) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        found.setdefault(name, []).append((begin, end))
    return lines, found


def without(platform, text, name):
    lines, found = blocks(platform, text)
    dropped = {index for begin, end in found[name] for index in range(begin, end)}
    return "".join(line for index, line in enumerate(lines) if index not in dropped)


def positive(platform, rule):
    folder = RULE_FIXTURES / rule.id
    policy_path = folder / "positive.policy.json"
    policy = management.load_policy(policy_path, platform) if policy_path.is_file() else None
    return (folder / "positive.conf").read_text(encoding="utf-8"), policy, policy_path


def expected_reason(platform, rule, text, policy, name):
    probe = engine._STATUS.get(rule.check)
    if probe is not None:
        state, reason = probe(PARSERS[platform].parse(text), policy)
        if state == NOT_EVALUATED:
            return reason
    return section_missing(name)


def outcome(platform, rule, text, policy):
    findings, states = evaluate(PARSERS[platform].parse(text), "tenant-example", "device-example", (rule,), policy)
    return states[rule.id], [f for f in findings if f.rule_id == rule.id]


@pytest.mark.parametrize(("platform", "rule"), CASES, ids=IDS)
def test_every_declared_section_is_present_in_the_positive_fixture(platform, rule):
    text, policy, _path = positive(platform, rule)
    _lines, found = blocks(platform, text)
    assert set(rule.sections) <= set(found)
    state, hits = outcome(platform, rule, text, policy)
    assert state == ("evaluated", "")
    assert hits


@pytest.mark.parametrize(("platform", "rule"), CASES, ids=IDS)
def test_removing_a_declared_section_leaves_the_rule_not_evaluated(platform, rule):
    text, policy, _path = positive(platform, rule)
    for name in rule.sections:
        cut = without(platform, text, name)
        state, hits = outcome(platform, rule, cut, policy)
        assert state == ("not-evaluated", expected_reason(platform, rule, cut, policy, name))
        assert hits == []


@pytest.mark.parametrize(("platform", "rule"), CASES, ids=IDS)
def test_removing_any_section_never_silences_an_evaluated_rule(platform, rule):
    text, policy, _path = positive(platform, rule)
    _lines, found = blocks(platform, text)
    for name in sorted(set(found) - set(rule.default_sections)):
        state, hits = outcome(platform, rule, without(platform, text, name), policy)
        assert state[0] != "evaluated" or hits, (rule.id, name)


@pytest.mark.parametrize(("platform", "rule"), CASES, ids=IDS)
def test_removing_a_default_section_keeps_the_rule_evaluated(platform, rule):
    text, policy, _path = positive(platform, rule)
    _lines, found = blocks(platform, text)
    shown = sorted(set(rule.default_sections) & set(found))
    assert shown or not rule.default_sections
    for name in shown:
        state, _hits = outcome(platform, rule, without(platform, text, name), policy)
        assert state == ("evaluated", ""), (rule.id, name)


def real_sections(device):
    return set((REAL_SECTIONS / ("%s.txt" % device)).read_text(encoding="utf-8").splitlines())


def as_shown(text, present):
    _lines, found = blocks("fortios", text)
    for name in sorted(set(found) - present):
        text = without("fortios", text, name)
    return text


@pytest.mark.parametrize("device", REAL_DEVICES)
@pytest.mark.parametrize("rule", [rule for platform, rule in CASES if platform == "fortios"],
                         ids=[rule.id for platform, rule in CASES if platform == "fortios"])
def test_a_rule_is_evaluated_on_the_sections_a_real_show_prints(device, rule):
    present = real_sections(device)
    assert set(rule.sections) <= present
    text, policy, _path = positive("fortios", rule)
    state, _hits = outcome("fortios", rule, as_shown(text, present), policy)
    assert state == ("evaluated", ""), (device, rule.id)


@pytest.mark.parametrize(("platform", "rule"), CASES, ids=IDS)
def test_a_missing_section_keeps_the_finding_out_of_gone(platform, rule, tmp_path, capsys):
    text, policy, policy_path = positive(platform, rule)
    text = complete(text, platform)
    for number, name in enumerate(rule.sections):
        store = tmp_path / ("audit-%d.sqlite" % number)
        runs = []
        for label, source in (("full", text), ("cut", without(platform, text, name))):
            argv = run_args(write_config(tmp_path, source, name="%s-%d.conf" % (label, number)),
                            as_json=True, store=store, platform=platform)
            if policy_path.is_file():
                argv += ["--policy", str(policy_path)]
            code, out, _err = invoke(capsys, argv)
            runs.append((code, json.loads(out)))
        before, after = runs[0][1], runs[1][1]
        assert [f["rule_id"] for f in before["findings"] if f["rule_id"] == rule.id]
        assert [item for item in after["gone"] if item["rule_id"] == rule.id] == []
        assert [item["rule_id"] for item in after["not_evaluated"] if item["rule_id"] == rule.id]
        cut = without(platform, text, name)
        assert after["rule_status"][rule.id]["reason"] == expected_reason(platform, rule, cut, policy, name)
        evaluated = {key for key, item in after["rule_status"].items() if item["status"] == "evaluated"}
        assert {item["rule_id"] for item in after["gone"]} <= evaluated
        if after["rule_status"][rule.id]["required"]:
            assert runs[1][0] == cli.EXIT_INCOMPLETE


RO_VIEW = (
    'config system admin\n    edit "netops-ro"\n        set accprofile "netops-ro"\n    next\nend\n'
    'config system accprofile\n    edit "netops-ro"\n        set sysgrp read\n    next\nend\n'
)
SUPER_VIEW = (
    'config system admin\n    edit "admin"\n        set accprofile "super_admin"\n    next\n'
    '    edit "netops-ro"\n        set accprofile "netops-ro"\n    next\nend\n'
)
GLOBAL_VIEW = 'config system global\n    set hostname "lab"\nend\n'
ADMIN_RULES = tuple(rule for _platform, rule in CASES
                    if rule.id in ("fortios.mgmt.default-admin-account", "fortios.mgmt.admin-no-trusthost"))
ADMIN_IDS = tuple(rule.id for rule in ADMIN_RULES)
SUPER_HITS = {"fortios.mgmt.default-admin-account": 1, "fortios.mgmt.admin-no-trusthost": 2}


@pytest.mark.parametrize("rule", ADMIN_RULES, ids=ADMIN_IDS)
def test_an_admin_list_without_a_super_admin_is_not_evaluated(rule):
    state, hits = outcome("fortios", rule, GLOBAL_VIEW + RO_VIEW, None)
    assert state == ("not-evaluated", "admin-visibility-unproven")
    assert hits == []


@pytest.mark.parametrize("rule", ADMIN_RULES, ids=ADMIN_IDS)
def test_an_admin_list_with_a_super_admin_is_evaluated(rule):
    state, hits = outcome("fortios", rule, GLOBAL_VIEW + SUPER_VIEW, None)
    assert state == ("evaluated", "")
    assert len(hits) == SUPER_HITS[rule.id]


def test_a_run_over_a_read_only_view_is_incomplete(tmp_path, capsys):
    text = complete((RULE_FIXTURES / "fortios.mgmt.wan-admin-access" / "negative.conf").read_text(encoding="utf-8"))
    text = without("fortios", text, "system admin") + RO_VIEW
    code, out, _err = invoke(capsys, run_args(write_config(tmp_path, text), as_json=True))
    report = json.loads(out)
    for rule in ADMIN_RULES:
        assert report["rule_status"][rule.id] == {"status": "not-evaluated", "reason": "admin-visibility-unproven",
                                                  "required": True}
    assert code == cli.EXIT_INCOMPLETE


def catalog_copy(tmp_path, monkeypatch, platform, change):
    folder = tmp_path / "catalog"
    shutil.copytree(engine.CATALOG_DIR, folder)
    path = folder / ("%s.json" % platform)
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document["rules"][1])
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(engine, "CATALOG_DIR", folder)
    return document["rules"][1]["id"]


@pytest.mark.parametrize("platform", sorted(PARSERS))
def test_catalog_refuses_a_rule_without_declared_sections(platform, tmp_path, monkeypatch):
    rule_id = catalog_copy(tmp_path, monkeypatch, platform, lambda item: item.pop("sections"))
    with pytest.raises(CatalogError, match="%s: sections are not declared" % re.escape(rule_id)):
        load_catalog(platform)


@pytest.mark.parametrize("value", ("system global", [""], [1]))
def test_catalog_refuses_sections_that_are_not_a_list_of_names(value, tmp_path, monkeypatch):
    rule_id = catalog_copy(tmp_path, monkeypatch, "fortios", lambda item: item.update(sections=value))
    with pytest.raises(CatalogError, match="%s: sections are not declared" % re.escape(rule_id)):
        load_catalog("fortios")


@pytest.mark.parametrize("value", ("user ldap", [""], [1]))
def test_catalog_refuses_default_sections_that_are_not_a_list_of_names(value, tmp_path, monkeypatch):
    rule_id = catalog_copy(tmp_path, monkeypatch, "fortios", lambda item: item.update(default_sections=value))
    with pytest.raises(CatalogError, match="%s: default sections are not a list of names" % re.escape(rule_id)):
        load_catalog("fortios")


def test_catalog_refuses_a_section_that_is_both_required_and_default(tmp_path, monkeypatch):
    rule_id = catalog_copy(tmp_path, monkeypatch, "fortios",
                           lambda item: item.update(default_sections=list(item["sections"])))
    with pytest.raises(CatalogError, match="%s: a section is both required and default" % re.escape(rule_id)):
        load_catalog("fortios")
