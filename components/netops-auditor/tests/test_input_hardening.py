import json
import os
import resource
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from netops_auditor import checks_fortios, cli, collect, l1_exos, l1_fortios, management, query
from netops_auditor import mcp_server
from netops_auditor.collect import CollectError
from netops_auditor.l1_fortios import Node
from netops_auditor.store import Store, StoreError
from netops_auditor.suppressions import SuppressionError, load_for_tenant
from test_cli import (
    DEVICE, FUTURE, EXPIRED, SECTIONS, TENANT, UTM_RULE, WAN_OBJECT, WAN_RULE, clean_text, dirty_text,
    file_inventory, full_args, gather, invoke, run_args, suppression, write_config, write_sarif,
    write_suppressions,
)

COMPONENT = Path(__file__).resolve().parents[1]
DEEP = "[" * 100000
VLAN_POLICY_RULE = "exos.management.vlan-policy"
INCOMPLETE_RULE = "fortios.snapshot.incomplete"


def run_json(capsys, argv):
    code, out, err = invoke(capsys, argv)
    return code, (json.loads(out) if out else None), err


def write_policy(directory, document, name="policy.json"):
    path = directory / name
    path.write_text(document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
    return path


def test_i1_superscript_admintimeout_is_not_a_number(tmp_path, capsys):
    path = write_config(tmp_path, "config system global\n    set admintimeout \u00b2\nend\n")
    code, report, err = run_json(capsys, run_args(path, as_json=True))
    assert (code, err) == (cli.EXIT_INCOMPLETE, "")
    assert report["rule_status"]["fortios.mgmt.idle-timeout"]["reason"] == "value-not-numeric"
    assert not [item for item in report["findings"] if item["rule_id"] == "fortios.mgmt.idle-timeout"]
    for value in ("\u00b2", "\u0661\u0662\u0660\u0660", "1\u00b2"):
        section = Node(path=("system global",), line=1, attrs={"admintimeout": l1_fortios.Attr(values=(value,), line=2)})
        assert checks_fortios._global_number(section, "admintimeout") is None
    section = Node(path=("system global",), line=1, attrs={"admintimeout": l1_fortios.Attr(values=("1200",), line=2)})
    assert checks_fortios._global_number(section, "admintimeout") == 1200


def test_i2_merge_sarif_refuses_every_malformed_shape(tmp_path, capsys):
    own = write_sarif(tmp_path, capsys, "fw-a", dirty_text(), "fw-a")
    good = json.loads(own.read_text(encoding="utf-8"))

    def variant(change):
        item = json.loads(json.dumps(good))
        change(item)
        return item

    cases = {
        "run-null": {"version": "2.1.0", "runs": [None]},
        "tool-null": {"version": "2.1.0", "runs": [{"tool": None}]},
        "driver-list": variant(lambda d: d["runs"][0]["tool"].__setitem__("driver", [])),
        "rules-dict": variant(lambda d: d["runs"][0]["tool"]["driver"].__setitem__("rules", {})),
        "rule-null": variant(lambda d: d["runs"][0]["tool"]["driver"]["rules"].append(None)),
        "rule-id-dict": variant(lambda d: d["runs"][0]["tool"]["driver"]["rules"][0].__setitem__("id", {})),
        "results-null": variant(lambda d: d["runs"][0].__setitem__("results", None)),
        "result-null": variant(lambda d: d["runs"][0]["results"].append(None)),
        "result-rule-list": variant(lambda d: d["runs"][0]["results"][0].__setitem__("ruleId", [])),
        "properties-list": variant(lambda d: d["runs"][0].__setitem__("properties", [])),
        "devices-dict": variant(lambda d: d["runs"][0]["properties"].__setitem__("devices", {"a": 1})),
        "device-null": variant(lambda d: d["runs"][0]["properties"]["devices"].append(None)),
    }
    for name, item in cases.items():
        path = tmp_path / (name + ".sarif")
        path.write_text(json.dumps(item), encoding="utf-8")
        output = tmp_path / (name + "-out.sarif")
        code, out, err = invoke(capsys, ["merge-sarif", "--output", str(output), str(path)])
        assert code == cli.EXIT_ERROR, name
        assert err.startswith("error: merge-sarif: ") and str(path) in err, (name, err)
        assert not output.exists(), name


def test_i2_issue_reproducer_is_a_controlled_error(tmp_path, capsys):
    path = tmp_path / "malformed.sarif"
    path.write_text('{"version":"2.1.0","runs":[null]}\n', encoding="utf-8")
    code, out, err = invoke(capsys, ["merge-sarif", "--output", str(tmp_path / "o.sarif"), str(path)])
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert err.startswith("error: merge-sarif: ")


def test_i3_backslash_at_the_end_of_a_quoted_value(tmp_path, capsys):
    text = 'config system global\n    set comments "folder\\\\"\n    set admintimeout 480\nend\n'
    tree = l1_fortios.parse(text)
    section = tree.section("system global")
    assert section.value("comments") == "folder\\"
    assert section.line_of("admintimeout") == 3
    lines = list(l1_fortios.logical_lines(text))
    assert [number for number, _ in lines] == [1, 2, 3, 4]
    escaped = 'config system global\n    set comments "say \\"hi\\" \\\\"\n    set hostname "a\nb"\nend\n'
    tree = l1_fortios.parse(escaped)
    assert tree.section("system global").value("comments") == 'say "hi" \\'
    assert tree.section("system global").value("hostname") == "a\nb"
    assert [number for number, _ in l1_fortios.logical_lines(escaped)] == [1, 2, 3, 5]
    continued = 'config system global\n    set comments "a\\"\nb"\n    set admintimeout 480\nend\n'
    tree = l1_fortios.parse(continued)
    assert tree.section("system global").value("comments") == 'a"\nb'
    assert tree.section("system global").line_of("admintimeout") == 4
    path = write_config(tmp_path, text)
    code, report, err = run_json(capsys, run_args(path, as_json=True))
    assert (code, err) == (0, "")
    assert [item["line"] for item in report["findings"] if item["rule_id"] == "fortios.mgmt.idle-timeout"] == [3]


def test_a2_vlan_tag_that_is_not_an_ascii_number_is_outside_the_policy(tmp_path, capsys):
    text = 'create vlan "v10"\nconfigure vlan v10 tag \u00b2\ncreate vlan "v20"\nconfigure vlan v20 tag 20\n'
    policy = write_policy(tmp_path, {"version": 1, "platform": "exos", "vlan_tags": [[1, 100]]})
    argv = run_args(write_config(tmp_path, text), as_json=True, platform="exos", device="sw1") + ["--policy", str(policy)]
    code, report, err = run_json(capsys, argv)
    assert (code, err) == (0, "")
    found = [item["object_key"] for item in report["findings"] if item["rule_id"] == VLAN_POLICY_RULE]
    assert found == ["vlan/v10"]
    tree = l1_exos.parse('create vlan "v30"\nconfigure vlan v30 tag \u0663\u0660\n')
    hits = list(management.hits("exos", "vlan-policy", tree, {"vlan_tags": [[1, 100]]}))
    assert [hit["object_key"] for hit in hits] == ["vlan/v30"]


def test_a3_rest_port_that_is_not_an_ascii_number_is_a_collect_error():
    for host in ("https://fw.example.invalid:\u00b2", "fw.example.invalid:\u0664\u0664\u0663", "fw.example.invalid:+443"):
        with pytest.raises(CollectError, match="host port"):
            collect._rest_target(host)
    assert collect._rest_target("https://fw.example.invalid:8443")[:2] == ("fw.example.invalid", 8443)


def truncated_dumps():
    base = clean_text()
    return {
        "edit": base + 'config firewall address\n    edit "a"\n',
        "quote": base + 'config firewall address\n    edit "a"\n        set comment "cut\n',
    }


@pytest.mark.parametrize("kind", ["edit", "quote"])
def test_a4_truncated_dump_in_collect_is_an_incomplete_snapshot(tmp_path, capsys, kind):
    text = truncated_dumps()[kind]
    path = write_config(tmp_path, text)
    inventory = file_inventory(tmp_path, path)
    code, out, err = gather(capsys, inventory, as_json=True)
    assert code == cli.EXIT_INCOMPLETE, err
    assert err == ""
    report = json.loads(out)
    assert [item["rule_id"] for item in report["findings"]] == [INCOMPLETE_RULE]
    evidence = report["findings"][0]["evidence"]
    assert evidence["missing_count"] == 0
    assert evidence["unterminated_line"] == len(clean_text().splitlines()) + (2 if kind == "edit" else 3)
    assert report["rule_status"][WAN_RULE] == {"status": "not-evaluated", "reason": "snapshot-incomplete", "required": True}
    policy = write_policy(tmp_path, {"version": 1, "platform": "fortios", "address_networks": ["192.0.2.0/24"]})
    code, out, err = invoke(capsys, ["collect", "--inventory", str(inventory), "--device", DEVICE,
                                     "--tenant", TENANT, "--json", "--policy", str(policy)])
    assert code == cli.EXIT_INCOMPLETE, err
    assert json.loads(out)["rules_version"].endswith(":" + management.policy_digest(management.load_policy(policy, "fortios")))


def test_a5_errors_keep_the_line_and_the_path(tmp_path, capsys):
    broken = write_config(tmp_path, "config system global\n    set hostname fw\nend\nend\n", name="broken.conf")
    code, out, err = invoke(capsys, run_args(broken))
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert str(broken) in err and "line 4" in err
    config = write_config(tmp_path, clean_text())
    policy = write_policy(tmp_path, '{"version": 1,\n "platform": "fortios",\n "address_networks": [}\n', name="bad-policy.json")
    code, out, err = invoke(capsys, run_args(config) + ["--policy", str(policy)])
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert str(policy) in err and "line 3" in err
    wrong = write_policy(tmp_path, {"version": 2, "platform": "fortios"}, name="wrong.json")
    code, out, err = invoke(capsys, run_args(config) + ["--policy", str(wrong)])
    assert code == cli.EXIT_ERROR
    assert str(wrong) in err and "policy version must be 1" in err


def test_a6_deep_nesting_is_a_controlled_error(tmp_path, capsys):
    config = write_config(tmp_path, clean_text())
    deep = tmp_path / "deep.json"
    deep.write_text(DEEP, encoding="utf-8")
    code, out, err = invoke(capsys, run_args(config) + ["--policy", str(deep)])
    assert (code, out) == (cli.EXIT_ERROR, "") and err.startswith("error: ")
    code, out, err = invoke(capsys, full_args(config, suppressions=deep))
    assert (code, out) == (cli.EXIT_ERROR, "") and err.startswith("error: suppressions: ")
    with pytest.raises(SuppressionError):
        load_for_tenant(deep, TENANT)
    with pytest.raises(management.PolicyError):
        management.load_policy(deep, "fortios")
    code, out, err = invoke(capsys, ["merge-sarif", "--output", str(tmp_path / "o.sarif"), str(deep)])
    assert (code, out) == (cli.EXIT_ERROR, "") and err.startswith("error: ")


def test_a7_store_that_is_not_a_database_is_a_store_error(tmp_path, capsys):
    config = write_config(tmp_path, clean_text())
    fake = tmp_path / "not-a-db.sqlite"
    fake.write_bytes(b"this is not a database at all\n" * 200)
    code, out, err = invoke(capsys, run_args(config, store=fake))
    assert (code, out) == (cli.EXIT_ERROR, "") and err.startswith("error: store: ")
    code, out, err = invoke(capsys, ["status", "--tenant", TENANT, "--device", DEVICE, "--store", str(fake)])
    assert (code, out) == (cli.EXIT_ERROR, "") and err.startswith("error: store: ")
    code, out, err = invoke(capsys, ["migrate-store", "--store", str(fake)])
    assert (code, out) == (cli.EXIT_ERROR, "") and err.startswith("error: store: ")
    with pytest.raises(StoreError):
        Store(fake)
    with pytest.raises(mcp_server.ConfigurationError):
        mcp_server.ReadOnlyStore(fake)


def test_a8_suppression_of_another_device_is_not_orphaned(tmp_path, capsys):
    config = write_config(tmp_path, dirty_text())
    foreign = suppression(UTM_RULE, "firewall policy/404", FUTURE, device="fw-other")
    foreign_expired = suppression(WAN_RULE, WAN_OBJECT, EXPIRED, device="fw-other")
    own = suppression(UTM_RULE, "firewall policy/404", FUTURE)
    waivers = write_suppressions(tmp_path, [foreign, foreign_expired, own])
    code, report, err = run_json(capsys, full_args(config, as_json=True, suppressions=waivers))
    assert code == 0, err
    assert [item["fingerprint"] for item in report["suppressions"]["orphaned"]] == [own["fingerprint"]]
    assert report["suppressions"]["expired"] == []


def duplicate_suppression_file(tmp_path):
    item = suppression(WAN_RULE, WAN_OBJECT, EXPIRED)
    body = json.dumps(item)
    assert body.count('"expires": "%s"' % EXPIRED) == 1
    body = body.replace('"expires": "%s"' % EXPIRED, '"expires": "%s", "expires": "%s"' % (EXPIRED, FUTURE))
    path = tmp_path / "duplicate.json"
    path.write_text('{"version": 2, "tenant": "%s", "suppressions": [%s]}' % (TENANT, body), encoding="utf-8")
    return path


def test_a9_duplicate_key_in_a_suppression_file_is_refused(tmp_path, capsys):
    path = duplicate_suppression_file(tmp_path)
    with pytest.raises(SuppressionError, match="duplicate key"):
        load_for_tenant(path, TENANT)
    config = write_config(tmp_path, dirty_text())
    code, out, err = invoke(capsys, full_args(config, suppressions=path))
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert "duplicate key" in err


def test_a9_duplicate_key_in_a_sarif_input_is_refused(tmp_path, capsys):
    own = write_sarif(tmp_path, capsys, "fw-a", dirty_text(), "fw-a")
    text = own.read_text(encoding="utf-8")
    twice = tmp_path / "twice.sarif"
    twice.write_text('{"version": "2.1.0",' + text.lstrip()[1:], encoding="utf-8")
    code, out, err = invoke(capsys, ["merge-sarif", "--output", str(tmp_path / "o.sarif"), str(twice)])
    assert code == cli.EXIT_ERROR and "duplicate key" in err


def test_a11_only_newline_ends_a_line(tmp_path):
    text = 'config system global\n    set comments "a\u2028b\u2029c\x85d\x0ce\rf"\n    set admintimeout 480\nend\n'
    tree = l1_fortios.parse(text)
    section = tree.section("system global")
    assert section.value("comments") == "a\u2028b\u2029c\x85d\x0ce\rf"
    assert section.line_of("admintimeout") == 3
    assert l1_fortios.parse(text.replace("\n", "\r\n")).section("system global").line_of("admintimeout") == 3
    exos = 'configure snmp sysName "a\u2028b\u2028c"\ncreate upm profile p\n# Module vlan configuration.\n.\nenable sntp-client\n'
    configuration = l1_exos.parse(exos)
    assert configuration.serialize() == exos
    assert configuration.commands[0].tokens[-1] == "a\u2028b\u2028c"
    assert configuration.first("enable", "sntp-client").line == 5
    assert configuration.upm_bodies == ((3, 4),)
    assert l1_exos.parse(exos.replace("\n", "\r\n")).first("enable", "sntp-client").line == 5
    assert collect.missing_sections(exos, ("vlan",), "exos") == ("vlan",)


def test_a12_address_unused_is_linear(monkeypatch):
    count = 3000
    lines = ["config firewall address"]
    for index in range(count):
        lines += ['    edit "a%d"' % index, "        set subnet 192.0.2.%d 255.255.255.255" % (index % 250 + 1), "    next"]
    lines += ["end", "config firewall addrgrp", '    edit "g"', '        set member "a1" "a2"', "    next", "end", ""]
    tree = l1_fortios.parse("\n".join(lines))
    nodes = sum(1 for _ in management.walk(tree))
    visited = []
    original = management.walk

    def counted(node):
        for item in original(node):
            visited.append(item)
            yield item
    monkeypatch.setattr(management, "walk", counted)
    hits = list(management.hits("fortios", "address-unused", tree))
    assert len(hits) == count - 2
    assert {"firewall address/a1", "firewall address/a2"}.isdisjoint(hit["object_key"] for hit in hits)
    assert len(visited) <= 2 * nodes


def test_a12_reference_from_the_own_entry_does_not_count():
    text = ('config firewall address\n    edit "a"\n        set associated-interface "a"\n    next\n'
            '    edit "b"\n        set associated-interface "a"\n    next\nend\n')
    hits = list(management.hits("fortios", "address-unused", l1_fortios.parse(text)))
    assert [hit["object_key"] for hit in hits] == ["firewall address/b"]


def fifo_writer(path, size):
    def write():
        try:
            with open(path, "wb") as stream:
                stream.write(b" " * size)
        except BrokenPipeError:
            pass
    thread = threading.Thread(target=write, daemon=True)
    thread.start()
    return thread


def test_a14_policy_from_a_pipe_is_refused(tmp_path, capsys):
    fifo = tmp_path / "policy.fifo"
    os.mkfifo(fifo)
    thread = fifo_writer(fifo, management.MAX_POLICY_BYTES + 64)
    config = write_config(tmp_path, clean_text())
    code, out, err = invoke(capsys, run_args(config) + ["--policy", str(fifo)])
    descriptor = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    try:
        while thread.is_alive():
            try:
                os.read(descriptor, 65536)
            except BlockingIOError:
                thread.join(0.01)
    finally:
        os.close(descriptor)
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert "policy is not a regular file" in err


def test_a14_policy_over_the_limit_is_refused(tmp_path, capsys):
    document = json.dumps({"version": 1, "platform": "fortios"})
    path = write_policy(tmp_path, document + " " * (management.MAX_POLICY_BYTES + 1 - len(document)))
    config = write_config(tmp_path, clean_text())
    code, out, err = invoke(capsys, run_args(config) + ["--policy", str(path)])
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert "policy is larger than %d bytes" % management.MAX_POLICY_BYTES in err


def test_a14_policy_at_the_limit_is_read(tmp_path, capsys):
    document = json.dumps({"version": 1, "platform": "fortios"})
    path = write_policy(tmp_path, document + " " * (management.MAX_POLICY_BYTES - len(document)))
    config = write_config(tmp_path, clean_text())
    code, out, err = invoke(capsys, run_args(config) + ["--policy", str(path)])
    assert code == cli.EXIT_OK, err


def limited():
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="needs /dev/zero")
def test_a14_policy_from_dev_zero_ends_with_an_error(tmp_path):
    config = write_config(tmp_path, clean_text())
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(
        (str(COMPONENT / "src"), str(COMPONENT.parent / "netops-core" / "src"))))
    argv = [sys.executable, "-B", "-m", "netops_auditor"] + run_args(config) + ["--policy", "/dev/zero"]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=environment, preexec_fn=limited)
    assert result.returncode == cli.EXIT_ERROR, result.stderr[-400:]
    assert "policy is not a regular file" in result.stderr
    assert "Traceback" not in result.stderr


def test_z1_baseline_and_history_are_read_inside_the_write_transaction(tmp_path, capsys, monkeypatch):
    database = tmp_path / "audit.sqlite"
    config = write_config(tmp_path, dirty_text())
    assert invoke(capsys, run_args(config, store=database))[0] == 0
    seen = []
    for name in ("baseline_fingerprints", "runs_for_device", "findings_for_run"):
        original = getattr(Store, name)

        def wrapped(self, *args, _original=original, _name=name, **kwargs):
            seen.append((_name, self._connection.in_transaction))
            return _original(self, *args, **kwargs)
        monkeypatch.setattr(Store, name, wrapped)
    code, _, err = invoke(capsys, run_args(config, store=database))
    assert code == 0, err
    names = {name for name, _ in seen}
    assert {"baseline_fingerprints", "runs_for_device"} <= names
    assert all(inside for _, inside in seen), seen
    inventory = file_inventory(tmp_path, config)
    seen.clear()
    code, _, err = invoke(capsys, ["collect", "--inventory", str(inventory), "--device", DEVICE, "--tenant", TENANT,
                                   "--store", str(database)])
    assert code == 0, err
    assert seen and all(inside for _, inside in seen), seen


def test_z2_historical_entries_carry_the_rule_status(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    config = write_config(tmp_path, dirty_text())
    assert invoke(capsys, run_args(config, store=database))[0] == 0
    narrow = file_inventory(tmp_path, config, sections=SECTIONS + ("vpn ipsec phase1-interface",), name="narrow.json")
    assert invoke(capsys, ["collect", "--inventory", str(narrow), "--device", DEVICE, "--tenant", TENANT,
                           "--store", str(database)])[0] == cli.EXIT_INCOMPLETE
    with Store(database) as store:
        now = datetime.now(timezone.utc)
        listing = query.list_findings(store, TENANT, DEVICE, now=now)
        historical = [item for item in listing["findings"] if item["state"] == "not-evaluated"]
        assert historical
        for item in historical:
            assert item["rule_status"] == {"status": "not-evaluated", "reason": "snapshot-incomplete"}
        marker = [item for item in listing["findings"] if item["rule_id"] == INCOMPLETE_RULE]
        assert marker and marker[0]["rule_status"] == {"status": "evaluated", "reason": ""}
        for item in listing["findings"]:
            assert set(item) == set(query.FINDING_KEYS)
        detail = query.finding_detail(store, TENANT, DEVICE, historical[0]["fingerprint"], now=now)
        assert detail["state"] == "not-evaluated"
        assert detail["rule_status"] == {"status": "not-evaluated", "reason": "snapshot-incomplete"}
        assert set(detail) == set(query.DETAIL_KEYS)


@pytest.mark.parametrize("attribute, rule_id", [
    ("admintimeout", "fortios.mgmt.idle-timeout"),
    ("admin-lockout-threshold", "fortios.mgmt.lockout-threshold"),
])
@pytest.mark.parametrize("value", ["\u00b2", "\u0661\u0662\u0660\u0660", "thirty", "-1", "1.5"])
def test_i1_a_non_numeric_global_number_leaves_its_rule_not_evaluated(tmp_path, capsys, attribute, rule_id, value):
    text = mutate_global(clean_text(), "    set %s %s\n" % (attribute, value))
    code, report, err = run_json(capsys, run_args(write_config(tmp_path, text), as_json=True))
    assert code == cli.EXIT_INCOMPLETE, err
    assert report["rule_status"][rule_id] == {"status": "not-evaluated", "reason": "value-not-numeric", "required": True}
    assert report["evaluation_complete"] is False
    assert not [item for item in report["findings"] if item["rule_id"] == rule_id]


@pytest.mark.parametrize("attribute, rule_id, value, found", [
    ("admintimeout", "fortios.mgmt.idle-timeout", "30", True),
    ("admintimeout", "fortios.mgmt.idle-timeout", "5", False),
    ("admin-lockout-threshold", "fortios.mgmt.lockout-threshold", "10", True),
    ("admin-lockout-threshold", "fortios.mgmt.lockout-threshold", "3", False),
])
def test_i1_a_numeric_global_number_is_evaluated(tmp_path, capsys, attribute, rule_id, value, found):
    text = mutate_global(clean_text(), "    set %s %s\n" % (attribute, value))
    code, report, err = run_json(capsys, run_args(write_config(tmp_path, text), as_json=True))
    assert code == cli.EXIT_OK, err
    assert report["rule_status"][rule_id]["status"] == "evaluated"
    assert bool([item for item in report["findings"] if item["rule_id"] == rule_id]) is found


def mutate_global(text, line):
    anchor = "config system global\n"
    assert text.count(anchor) == 1
    return text.replace(anchor, anchor + line)
