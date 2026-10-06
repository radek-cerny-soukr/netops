import json
import sqlite3
import threading

import pytest

from netops_auditor import cli, collect, l1_exos, management, sarif
from netops_auditor.engine import load_catalog
from netops_auditor.store import Store
from test_cli import TENANT, DEVICE, clean_text, file_inventory, gather, invoke, run_args, write_config

EXOS_BASE = (
    "#\n# Module vlan configuration.\n#\n"
    'create vlan "users"\nconfigure vlan users tag 10\n'
    "configure vlan users add ports 10 untagged\n"
    "#\n# Module ems configuration.\n#\nconfigure syslog add 192.0.2.9 local1\n"
    "#\n# Module netTools configuration.\n#\nconfigure sntp-client primary 192.0.2.1\nenable sntp-client\n"
    "#\n# Module telnetd configuration.\n#\ndisable telnet\n"
)
EXOS_RULES = {rule.id for rule in load_catalog("exos")}
FORTIOS_RULES = {rule.id for rule in load_catalog("fortios")}
MEMBERSHIP = ("exos.management.port-policy", "exos.management.port-native")


def exos(capsys, tmp_path, text, policy=None, store=None, name="sw.conf"):
    argv = run_args(write_config(tmp_path, text, name=name), as_json=True, platform="exos", device="sw1", store=store)
    if policy is not None:
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(dict({"version": 1, "platform": "exos"}, **policy)))
        argv += ["--policy", str(path)]
    code, out, err = invoke(capsys, argv)
    return code, (json.loads(out) if out else None), err


def statuses(report, value):
    return sorted(rule for rule, item in report["rule_status"].items() if item["status"] == value)


def test_a1_all_and_slot_ranges_without_port_inventory_are_not_evaluated_not_a_crash(tmp_path, capsys):
    text = EXOS_BASE + 'create vlan "v10"\nconfigure vlan v10 tag 11\nconfigure vlan v10 add ports all tagged\n'
    text += 'configure ports 1:1-2:4 display-string "uplink"\n'
    code, report, err = exos(capsys, tmp_path, text, name="bare.conf")
    assert (code, err) == (0, "")
    assert report["rule_status"]["exos.management.port-native"]["reason"] == "unresolved-port-list"
    policy = {"port_vlans": {"10": {"tagged": [], "untagged": ["users"]}}, "description_glob": "*"}
    code, report, err = exos(capsys, tmp_path, text, policy)
    assert (code, err) == (0, "")
    for rule in MEMBERSHIP + ("exos.management.port-description",):
        assert report["rule_status"][rule] == {"status": "not-evaluated", "reason": "unresolved-port-list", "required": False}
    assert report["rule_status"]["exos.management.vlan-empty"]["status"] == "evaluated"
    assert report["evaluation_complete"] is True
    assert not [f for f in report["findings"] if f["rule_id"] in MEMBERSHIP]


def test_a1_unresolved_mandatory_rule_is_a_refusal_not_a_traceback(tmp_path, capsys):
    text = EXOS_BASE + "configure vlan users add ports all tagged\n"
    policy = {"required_rules": ["port-policy"], "port_vlans": {"10": {"tagged": [], "untagged": ["users"]}}}
    code, report, err = exos(capsys, tmp_path, text, policy)
    assert code == 2 and report is None
    assert err == "error: mandatory policy rules not evaluated: port-policy\n"


def test_a1_port_inventory_of_the_snapshot_resolves_all_and_slot_ranges(tmp_path, capsys):
    text = EXOS_BASE.replace("ports 10 untagged", "ports 1:2-2:1 untagged")
    text = text.replace("#\n# Module vlan configuration.\n#\n",
                        "#\n# Module vlan configuration.\n#\nconfigure vr VR-Default delete ports 1:1-1:4,2:1-2:4\n")
    text += 'create vlan "v10"\nconfigure vlan v10 tag 11\nconfigure vlan v10 add ports all tagged\n'
    policy = {"port_vlans": {"1:3": {"tagged": [], "untagged": ["users"]}}}
    code, report, _ = exos(capsys, tmp_path, text, policy)
    assert code == 0
    for rule in MEMBERSHIP:
        assert report["rule_status"][rule]["status"] == "evaluated"
    found = sorted((f["rule_id"], f["object_key"]) for f in report["findings"] if f["rule_id"] in MEMBERSHIP)
    assert found == [("exos.management.port-policy", "ports/1:3/tagged/v10")]
    inventory = {"1:1", "1:2", "1:3", "1:4", "2:1", "2:2", "2:3", "2:4"}
    assert management.ports("all", inventory) == inventory
    assert management.ports("1:3-2:2", inventory) == {"1:3", "1:4", "2:1", "2:2"}
    for bad in ("1:3-2:9", "1-2:2", "all"):
        with pytest.raises(management.PolicyError):
            management.ports(bad, inventory if bad != "all" else None)


UPM_ACTIVE = (
    "#\n# Module vlan configuration.\n#\n"
    'create vlan "OFFICE"\nconfigure vlan OFFICE tag 10\nconfigure vlan OFFICE add ports 1-4 untagged\n'
    "#\n# Module upm configuration.\n#\n"
)
UPM_BODY = (
    "create upm profile dormant\n"
    "configure sntp-client primary 192.0.2.1\nenable sntp-client\n"
    "configure syslog add 192.0.2.9 local1\ndisable telnet\n"
    "configure snmpv3 add community public name public user v1v2c_ro\n"
)


def test_netops_009_upm_profile_body_is_not_active_configuration(tmp_path, capsys):
    _, plain, _ = exos(capsys, tmp_path, UPM_ACTIVE, name="plain.conf")
    _, wrapped, _ = exos(capsys, tmp_path, UPM_ACTIVE + UPM_BODY + ".\n", name="upm.conf")
    expected = ["exos.logging.no-syslog-target", "exos.mgmt.telnet-enabled", "exos.time.no-sntp-client"]
    assert sorted(f["rule_id"] for f in plain["findings"]) == expected
    assert sorted(f["rule_id"] for f in wrapped["findings"]) == expected
    configuration = l1_exos.parse(UPM_ACTIVE + UPM_BODY + ".\nenable telnet\n")
    assert configuration.first("enable", "sntp-client") is None
    assert configuration.first("enable", "telnet").line == 17
    assert [c.text for c in configuration.commands if c.upm_profile == "dormant"][-1] == "."


def test_netops_009_unterminated_upm_profile_leaves_the_catalog_unevaluated(tmp_path, capsys):
    code, report, _ = exos(capsys, tmp_path, UPM_ACTIVE + UPM_BODY)
    assert code == cli.EXIT_INCOMPLETE
    assert report["evaluation_complete"] is False and report["evaluation"] == "not-evaluated"
    assert report["findings"] == []
    assert statuses(report, "not-evaluated") == sorted(EXOS_RULES)
    assert {item["reason"] for item in report["rule_status"].values()} == {"unterminated-upm-profile"}


def comment_dump(header):
    return (
        "config firewall address\n"
        '    edit "lan-net"\n        set subnet 198.51.100.0 255.255.255.0\n'
        '        set comment "pasted from runbook:\n%s\nend"\n' % header
        + "    next\nend\n"
    )


def test_netops_011_section_header_inside_a_quoted_value_is_not_a_section():
    assert collect.missing_sections(comment_dump("config system global"), ["system global"], "fortios") == ("system global",)
    real = comment_dump("x") + "config system global\n    set hostname fw\nend\n"
    assert collect.missing_sections(real, ["system global"], "fortios") == ()
    text = "create upm profile p\n# Module vlan configuration.\n.\n"
    assert collect.missing_sections(text, ["vlan"], "exos") == ("vlan",)
    truncated = 'config system global\n set alias "open\nconfig system admin\n'
    assert collect.missing_sections(truncated, ["system global", "system admin"], "fortios") == ("system admin",)
    assert collect.unterminated_line(truncated, "fortios") == 2


def test_netops_011_quoted_header_leaves_the_collected_run_unevaluated(tmp_path, capsys):
    path = write_config(tmp_path, comment_dump("config system global"))
    code, out, _ = gather(capsys, file_inventory(tmp_path, path, sections=("system global",)), as_json=True)
    report = json.loads(out)
    assert code == cli.EXIT_INCOMPLETE
    assert [f["rule_id"] for f in report["findings"]] == ["fortios.snapshot.incomplete"]
    assert statuses(report, "not-evaluated") == sorted(FORTIOS_RULES)
    assert {item["reason"] for item in report["rule_status"].values()} == {"snapshot-incomplete"}


N012_BODY = (
    'create vlan "users"\nconfigure vlan users tag 10\ncreate vlan "guest"\nconfigure vlan guest tag 999\n'
    "configure vlan users add ports 10 untagged\nconfigure vlan guest add ports 10 untagged\n"
    'configure ports 10 display-string "printer"\n'
)
N012_POLICY = {"vlan_tags": [[1, 100]], "port_vlans": {"10": {"tagged": [], "untagged": ["users"]}},
               "description_glob": "user-*"}
N012_RULES = ["exos.management.port-description", "exos.management.port-native", "exos.management.port-policy",
              "exos.management.vlan-empty", "exos.management.vlan-policy"]


def management_view(report):
    found = sorted((f["rule_id"], f["object_key"]) for f in report["findings"] if ".management." in f["rule_id"])
    state = {rule: report["rule_status"][rule]["status"] for rule in N012_RULES}
    return found, state, report["rule_coverage"]


def test_netops_012_coverage_follows_the_evaluated_content_not_the_module_header(tmp_path, capsys):
    _, with_header, _ = exos(capsys, tmp_path, "#\n# Module vlan configuration.\n#\n" + N012_BODY, N012_POLICY, name="a.conf")
    _, without, _ = exos(capsys, tmp_path, "#\n# Module vcm configuration.\n#\n" + N012_BODY, N012_POLICY, name="b.conf")
    assert set(without["rule_coverage"].values()) == {"evaluated"}
    assert management_view(with_header) == management_view(without)
    assert len(management_view(without)[0]) == 4


def test_netops_012_module_header_without_content_is_not_evaluated(tmp_path, capsys):
    code, report, _ = exos(capsys, tmp_path, "#\n# Module vlan configuration.\n#\n", N012_POLICY)
    assert set(report["rule_coverage"].values()) == {"not-evaluated"}
    assert code == 0
    assert {report["rule_status"][rule]["reason"] for rule in N012_RULES} == {"no-vlan-content"}
    assert management_view(report)[0] == []
    required = dict(N012_POLICY, required_rules=["port-policy"])
    code, report, err = exos(capsys, tmp_path, "#\n# Module vlan configuration.\n#\n", required)
    assert (code, report) == (2, None)
    assert "mandatory policy rules not evaluated: port-policy" in err


GLOBAL = (
    'config system global\n    set hostname "fw"\n    set strong-crypto disable\n'
    "    set admin-https-ssl-versions tlsv1-0 tlsv1-2\nend\n"
)


@pytest.mark.parametrize("text,key", [
    ("config global\n" + GLOBAL + "end\n", "global"),
    ("config vdom\nedit root\nnext\nend\nconfig global\n" + GLOBAL + "end\n", "vdom"),
])
def test_netops_015_global_wrapper_is_never_a_clean_result(tmp_path, capsys, text, key):
    code, out, _ = invoke(capsys, run_args(write_config(tmp_path, text), as_json=True))
    report = json.loads(out)
    assert [(f["rule_id"], f["object_key"]) for f in report["findings"]] == [("fortios.scope.vdom-unsupported", key)]
    assert report["evaluation"] == "not-evaluated"
    assert code == cli.EXIT_INCOMPLETE and report["evaluation_complete"] is False
    for rule in ("fortios.crypto.strong-crypto-disabled", "fortios.mgmt.gui-legacy-tls"):
        assert report["rule_status"][rule] == {"status": "unsupported", "reason": "fortios.scope.vdom-unsupported",
                                                "required": True}


def history(store):
    connection = sqlite3.connect(str(store))
    try:
        return [row[0].split(":")[3:] for row in connection.execute("SELECT rules_version FROM runs ORDER BY id")]
    finally:
        connection.close()


@pytest.mark.parametrize("command", ["run", "collect"])
def test_netops_016_policy_history_is_checked_inside_the_write_transaction(tmp_path, monkeypatch, command):
    config = write_config(tmp_path, clean_text())
    inventory = file_inventory(tmp_path, config)
    store = tmp_path / "audit.sqlite"
    policies = {}
    for name in "ab":
        policies[name] = tmp_path / ("policy-%s.json" % name)
        policies[name].write_text(json.dumps({"version": 1, "platform": "fortios", "protected_groups": [name]}))
    barrier = threading.Barrier(2, timeout=20)
    original = Store.record_run

    def record_run(self, *args, **kwargs):
        barrier.wait()
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Store, "record_run", record_run)
    codes = {}

    def write(name):
        if command == "run":
            argv = run_args(config, as_json=True, store=store)
        else:
            argv = ["collect", "--inventory", str(inventory), "--device", DEVICE, "--tenant", TENANT,
                    "--store", str(store), "--json"]
        codes[name] = cli.main(argv + ["--policy", str(policies[name])])

    threads = [threading.Thread(target=write, args=(name,)) for name in "ab"]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(codes.values()) == [0, 2]
    assert len(history(store)) == 1


def test_k6_every_rule_carries_a_status_in_json_sarif_and_store(tmp_path, capsys):
    store = tmp_path / "audit.sqlite"
    config = write_config(tmp_path, clean_text())
    code, out, _ = invoke(capsys, run_args(config, as_json=True, store=store))
    report = json.loads(out)
    assert code == 0 and report["evaluation_complete"] is True and "evaluation" not in report
    assert set(report["rule_status"]) == FORTIOS_RULES
    for rule, item in report["rule_status"].items():
        assert set(item) == {"status", "reason", "required"}
        assert item["required"] is (".management." not in rule)
        assert item["status"] in ("evaluated", "not-evaluated", "unsupported")
        if ".management." not in rule:
            assert item == {"status": "evaluated", "reason": "", "required": True}
    code, out, _ = invoke(capsys, run_args(config) + ["--sarif"])
    device = json.loads(out)["runs"][0]["properties"]["devices"][0]
    assert device["rule_status"] == report["rule_status"] and device["evaluation_complete"] is True
    with Store(store) as db:
        run_id = db.last_run(TENANT, DEVICE)["id"]
        assert db.rule_status_for_run(TENANT, run_id) == report["rule_status"]


def test_k6_findings_of_a_rule_that_could_not_evaluate_are_not_reported_gone(tmp_path, capsys):
    store = tmp_path / "audit.sqlite"
    policy = {"port_vlans": {"10": {"tagged": [], "untagged": ["guest"]}, "11": {"tagged": [], "untagged": ["users"]}}}
    _, first, _ = exos(capsys, tmp_path, EXOS_BASE, policy, store=store)
    assert [f["rule_id"] for f in first["findings"] if f["rule_id"] in MEMBERSHIP] == [
        "exos.management.port-native", "exos.management.port-policy"]
    code, second, _ = exos(capsys, tmp_path, EXOS_BASE + "configure vlan users add ports all tagged\n", policy, store=store)
    assert code == 0
    assert second["gone"] == []
    assert sorted(item["rule_id"] for item in second["not_evaluated"]) == sorted(MEMBERSHIP)


def test_k6_status_of_a_stored_run_with_an_unevaluated_catalog_is_incomplete(tmp_path, capsys):
    from datetime import datetime, timezone
    from netops_auditor import query
    store = tmp_path / "audit.sqlite"
    exos(capsys, tmp_path, UPM_ACTIVE + UPM_BODY, store=store)
    code, out, _ = invoke(capsys, ["status", "--tenant", TENANT, "--device", "sw1", "--store", str(store), "--json"])
    assert code == 1 and json.loads(out)["state"] == "incomplete"
    with Store(store) as db:
        status = query.audit_status(db, TENANT, "sw1", now=datetime.now(timezone.utc))
    assert status["devices"][0]["state"] == "incomplete"
    assert set(status["devices"][0]["rule_status"]) == EXOS_RULES


def test_netops_016_a_policy_check_outside_the_write_lock_would_admit_both_writers(tmp_path, monkeypatch):
    config = write_config(tmp_path, clean_text())
    store = tmp_path / "audit.sqlite"
    policies = {}
    for name in "ab":
        policies[name] = tmp_path / ("policy-%s.json" % name)
        policies[name].write_text(json.dumps({"version": 1, "platform": "fortios", "protected_groups": [name]}))
    barrier = threading.Barrier(2, timeout=1)
    original = cli._policy_scope

    def policy_scope(rules_version):
        admit = original(rules_version)

        def checked(previous):
            admit(previous)
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
        return checked

    monkeypatch.setattr(cli, "_policy_scope", policy_scope)
    codes = {}

    def write(name):
        codes[name] = cli.main(run_args(config, as_json=True, store=store) + ["--policy", str(policies[name])])

    threads = [threading.Thread(target=write, args=(name,)) for name in "ab"]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(codes.values()) == [0, 2]
    assert len(history(store)) == 1
