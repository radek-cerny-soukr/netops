import json
from pathlib import Path

import pytest

from netops_auditor import checks_exos, checks_fortios, l1_exos, l1_fortios, management
from netops_auditor.engine import load_catalog, run

FIXTURES = Path(__file__).parent / "fixtures" / "rules"
CASES = [(platform, name) for platform, rules in management.RULES.items() for name in rules]


def evaluate(platform, text, name, policy=None):
    parser = l1_fortios if platform == "fortios" else l1_exos
    selected = [r for r in load_catalog(platform) if r.id == platform + ".management." + name]
    assert len(selected) == 1
    return run(parser.parse(text), "tenant-example", "device-example", selected, policy)


@pytest.mark.parametrize("platform,name", CASES)
def test_every_management_rule_has_executable_positive_and_negative_fixtures(platform, name):
    directory = FIXTURES / (platform + ".management." + name)
    for variant, expected in (("positive", 1), ("negative", 0)):
        text = (directory / (variant + ".conf")).read_text()
        policy = management.load_policy(directory / (variant + ".policy.json"), platform)
        findings = evaluate(platform, text, name, policy)
        assert len(findings) == expected
        for finding in findings:
            assert set(dict(finding.evidence)) == {"code", "count"}
            assert "192.0.2." not in json.dumps(finding.as_dict())
            assert "00:00:5e" not in json.dumps(finding.as_dict())


def test_conflict_identity_distinguishes_each_pair_and_is_stable_on_reordering():
    text = (FIXTURES / "fortios.management.dhcp-conflict/positive.conf").read_text()
    first = evaluate("fortios", text, "dhcp-conflict")
    text += "\nconfig system global\n set hostname ignored\nend\n"
    assert [f.fingerprint() for f in first] == [f.fingerprint() for f in evaluate("fortios", text, "dhcp-conflict")]
    additional = " edit 3\n set ip 192.0.2.20\n set mac 00:00:5e:00:53:03\n next\n"
    text = text.replace(" config reserved-address\n", " config reserved-address\n" + additional)
    assert len(evaluate("fortios", text, "dhcp-conflict")) == 3


@pytest.mark.parametrize("attribute,value", [("action", "block"), ("action", "assign"), ("type", "option82")])
def test_non_mac_reservations_and_non_reserved_actions_are_not_misclassified(attribute, value):
    text = (FIXTURES / "fortios.management.dhcp-conflict/positive.conf").read_text()
    text = text.replace(" edit 2\n", " edit 2\n set " + attribute + " " + value + "\n")
    assert evaluate("fortios", text, "dhcp-conflict") == ()


def test_disabled_server_is_not_reported_as_active_reservation_conflict():
    text = (FIXTURES / "fortios.management.dhcp-conflict/positive.conf").read_text()
    text = text.replace(" set default-gateway", " set status disable\n set default-gateway")
    assert evaluate("fortios", text, "dhcp-conflict") == ()


def test_port_range_and_stack_range_expansion_is_bounded():
    assert management.ports("1,3-5,2:1-2:3") == {"1", "3", "4", "5", "2:1", "2:2", "2:3"}
    for bad in ("all", "1-999999", "2:1-3:2", "5-2", "0", "1;reboot"):
        with pytest.raises(management.PolicyError):
            management.ports(bad)


def test_missing_policy_and_missing_snapshot_are_reported():
    tree = l1_exos.parse("")
    assert management.coverage("exos", tree)["vlan-policy"] == "not-configured"
    assert management.coverage("exos", tree, {"vlan_tags": [[2, 100]]})["vlan-policy"] == "not-evaluated"


@pytest.mark.parametrize("data", [
    {"version": True, "platform": "exos"},
    {"version": 1, "platform": "fortios"},
    {"version": 1, "platform": "exos", "vlan_tags": [[100, 2]]},
    {"version": 1, "platform": "exos", "port_vlans": {"all": {"tagged": [], "untagged": []}}},
    {"version": 1, "platform": "exos", "required_rules": ["invented-rule"]},
    {"version": 1, "platform": "exos", "ignore_all": True},
])
def test_invalid_policy_is_rejected(data):
    with pytest.raises(management.PolicyError):
        management.validate_policy(data, "exos")


def test_upm_script_body_does_not_look_like_current_vlan_membership():
    text = "# Module vlan configuration.\nconfigure vlan guest add ports 10 untagged\n"
    text += "# Module upm configuration.\ncreate upm profile example\nconfigure vlan old add ports 10 untagged\n.\n"
    assert evaluate("exos", text, "port-native") == ()


def test_dynamic_group_is_not_reported_as_empty_static_group():
    text = 'config firewall addrgrp\n edit "group-example"\n set type dynamic\n next\nend\n'
    assert evaluate("fortios", text, "group-empty") == ()


def test_long_cycle_is_reported_without_recursion():
    text = "config firewall addrgrp\n" + "".join(
        'edit "g%d"\nset member "g%d"\nnext\n' % (i, (i + 1) % 1100) for i in range(1100)
    ) + "end\n"
    assert len(evaluate("fortios", text, "group-cycle")) == 1100

def test_changing_or_removing_policy_cannot_resolve_historical_findings(tmp_path, capsys):
    from netops_auditor import cli
    from netops_auditor.store import Store
    from test_cli import run_args, write_config, clean_text
    config = write_config(tmp_path, clean_text())
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1, "platform": "fortios", "address_networks": ["198.51.100.0/24"]}))
    store = tmp_path / "audit.sqlite"
    args = run_args(config, as_json=True, store=store)
    assert cli.main(args + ["--policy", str(path)]) in (0, 1)
    capsys.readouterr()
    assert cli.main(args) == 2
    assert "policy differs" in capsys.readouterr().err
    with Store(store) as db:
        assert len(db.runs_for_device("tenant-a", "fw-example")) == 1

def test_cycles_only_report_edges_inside_a_strongly_connected_component():
    graph = {"a": {"b"}, "b": {"c", "leaf"}, "c": {"a"}, "leaf": set(), "start": {"a"}, "self": {"self"}}
    assert management._cyclic_edges(graph) == {("a", "b"), ("b", "c"), ("c", "a"), ("self", "self")}
