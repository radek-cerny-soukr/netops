import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from netops_auditor import checks_exos
from netops_auditor import cli
from netops_auditor import query
from netops_auditor.engine import load_catalog, run
from netops_auditor.l1_exos import parse
from netops_auditor.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
RULE_FIXTURES = FIXTURES / "rules"
CLEAN = FIXTURES / "exos_clean.conf"
CANARY = FIXTURES / "secret_canary_exos.conf"

POSITIVE = "positive.conf"
NEGATIVE = "negative.conf"

PLATFORM = "exos"
TENANT = "tenant-gate"
DEVICE = "sw-gate.example.invalid"
NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=timezone.utc)

RULES = load_catalog(PLATFORM)
RULE_IDS = tuple(rule.id for rule in RULES)

MARKERS = tuple("KANARCI-TAJEMSTVI-EXOS-%02d" % number for number in range(1, 12))

DEFECTS = {
    "exos.time.no-sntp-client": (
        "configure sntp-client primary 192.0.2.1\nenable sntp-client\n",
        "",
    ),
    "exos.logging.no-syslog-target": (
        "configure syslog add 192.0.2.9 local1\n",
        "",
    ),
    "exos.snmp.default-community": (
        "configure snmpv3 add community office-index name office-read user v1v2c_ro\n",
        "configure snmpv3 add community office-index name office-read user v1v2c_ro\n"
        "configure snmp add community readonly public\n",
    ),
    "exos.mgmt.telnet-enabled": (
        "disable telnet\n",
        "",
    ),
}

VOLATILE = '''#
# Module devmgr configuration.
#
configure snmp sysName "sw-example"
#
# Module aaa configuration.
#
configure account admin encrypted "%s"
#
# Module snmpMaster configuration.
#
configure snmp add community readonly public
#
# Module telnetd configuration.
#
disable telnet
'''

VOLATILE_FIRST = "JDEkRVhBTVBMRTAxJGV4YW1wbGVoYXNoQTAx"
VOLATILE_SECOND = "JDEkRVhBTVBMRTAyJGV4YW1wbGVoYXNoQjAy"


def text_of(path):
    return path.read_text(encoding="utf-8")


def folder_of(rule_id):
    return RULE_FIXTURES / rule_id


def audit(text):
    return run(parse(text), TENANT, DEVICE, RULES)


def dumped(value):
    return json.dumps(value, ensure_ascii=False, default=str)


def encoded(findings):
    return dumped([finding.as_dict() for finding in findings]).encode("utf-8")


def mutated(text, old, new):
    assert text.count(old) == 1
    return text.replace(old, new)


def defective(rule_id):
    old, new = DEFECTS[rule_id]
    return mutated(text_of(CLEAN), old, new)


def run_argv(config_path, store_path=None, as_json=False):
    argv = [
        "run",
        "--platform",
        PLATFORM,
        "--tenant",
        TENANT,
        "--device",
        DEVICE,
        "--config",
        str(config_path),
    ]
    if store_path is not None:
        argv.extend(["--store", str(store_path)])
    if as_json:
        argv.append("--json")
    return argv


def invoke(capsys, argv):
    code = cli.main(argv)
    captured = capsys.readouterr()
    assert code == 0
    return captured.out, captured.err


def written(directory, text, name="export.conf"):
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def test_gate_the_catalog_carries_every_rule_of_the_release():
    assert sorted(RULE_IDS) == sorted(DEFECTS)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_gate_every_rule_carries_a_positive_and_a_negative_fixture(rule_id):
    folder = folder_of(rule_id)
    assert folder.is_dir()
    for name in (POSITIVE, NEGATIVE):
        path = folder / name
        assert path.is_file()
        assert text_of(path).strip()


def test_gate_every_rule_names_an_implemented_check():
    assert all(hasattr(checks_exos, rule.check) for rule in RULES)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_gate_the_positive_fixture_yields_exactly_one_finding(rule_id):
    findings = audit(text_of(folder_of(rule_id) / POSITIVE))
    assert [finding.rule_id for finding in findings] == [rule_id]


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_gate_the_negative_fixture_silences_the_rule(rule_id):
    findings = audit(text_of(folder_of(rule_id) / NEGATIVE))
    assert [finding for finding in findings if finding.rule_id == rule_id] == []


def test_gate_the_clean_fixture_yields_no_finding():
    assert audit(text_of(CLEAN)) == ()


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_gate_one_inserted_defect_yields_exactly_one_new_finding(rule_id):
    before = set(audit(text_of(CLEAN)))
    after = audit(defective(rule_id))
    new = [finding for finding in after if finding not in before]
    assert [finding.rule_id for finding in new] == [rule_id]


def test_gate_no_secret_reaches_a_finding_a_query_or_a_report(tmp_path, capsys):
    text = text_of(CANARY)
    for marker in MARKERS:
        assert text.count(marker) == 1
    findings = audit(text)
    assert len(findings) >= 1
    blobs = [dumped([finding.as_dict() for finding in findings])]
    config = written(tmp_path, text, "canary.conf")
    store = tmp_path / "audit.sqlite3"
    for as_json in (True, False):
        out, err = invoke(capsys, run_argv(config, store, as_json))
        blobs.append(out)
        blobs.append(err)
    with Store(store) as opened:
        listing = query.list_findings(opened, TENANT, DEVICE, now=NOW, group_by="object")
        assert listing["total"] >= 1
        blobs.append(dumped(listing))
        blobs.append(dumped(query.audit_status(opened, TENANT, now=NOW)))
        blobs.append(dumped(query.list_rules(RULES)))
        for rule in RULES:
            blobs.append(dumped(query.rule_detail(RULES, rule.id)))
        for item in listing["findings"]:
            detail = query.finding_detail(opened, TENANT, DEVICE, item["fingerprint"], now=NOW)
            assert detail is not None
            blobs.append(dumped(detail))
        runs = tuple(opened.runs_for_device(TENANT, DEVICE))
        assert len(runs) == 2
        blobs.append(dumped(query.compare(opened, TENANT, DEVICE, runs[1]["id"], runs[0]["id"])))
    joined = "\n".join(blobs)
    for marker in MARKERS:
        assert marker not in joined


def test_gate_the_same_input_yields_a_byte_identical_engine_output():
    text = text_of(CANARY)
    first = audit(text)
    second = audit(text)
    assert first == second
    assert encoded(first) == encoded(second)
    assert list(first) == sorted(first, key=lambda finding: (finding.rule_id, finding.object_key))


def test_gate_the_same_input_yields_a_byte_identical_report(tmp_path, capsys):
    config = written(tmp_path, text_of(CANARY), "canary.conf")
    first_out, first_err = invoke(capsys, run_argv(config, as_json=True))
    second_out, second_err = invoke(capsys, run_argv(config, as_json=True))
    assert first_out.encode("utf-8") == second_out.encode("utf-8")
    assert first_err == second_err == ""


def test_gate_the_same_store_yields_a_byte_identical_listing(tmp_path, capsys):
    config = written(tmp_path, text_of(CANARY), "canary.conf")
    store = tmp_path / "audit.sqlite3"
    invoke(capsys, run_argv(config, store))
    with Store(store) as opened:
        first = query.list_findings(opened, TENANT, DEVICE, now=NOW, group_by="object")
        second = query.list_findings(opened, TENANT, DEVICE, now=NOW, group_by="object")
    assert dumped(first).encode("utf-8") == dumped(second).encode("utf-8")
    assert [item["fingerprint"] for item in first["findings"]] == [
        item["fingerprint"] for item in second["findings"]
    ]


def test_gate_a_volatile_field_does_not_move_the_findings(tmp_path, capsys):
    first_text = VOLATILE % VOLATILE_FIRST
    second_text = VOLATILE % VOLATILE_SECOND
    assert first_text != second_text
    differing = [
        (left, right)
        for left, right in zip(first_text.splitlines(), second_text.splitlines())
        if left != right
    ]
    assert len(differing) == 1
    assert "configure account" in differing[0][0]
    assert len(first_text.splitlines()) == len(second_text.splitlines())
    left = [finding.as_dict() for finding in audit(first_text)]
    right = [finding.as_dict() for finding in audit(second_text)]
    assert len(left) >= 1
    assert [item for item in right if item not in left] == []
    assert [item for item in left if item not in right] == []
    assert dumped(left).encode("utf-8") == dumped(right).encode("utf-8")
    reports = []
    for index, text in enumerate((first_text, second_text)):
        config = written(tmp_path, text, "export-%d.conf" % index)
        out, _ = invoke(capsys, run_argv(config, as_json=True))
        reports.append(json.loads(out))
    assert reports[0]["snapshot_sha256"] != reports[1]["snapshot_sha256"]
    assert reports[0]["findings"] == reports[1]["findings"]
    assert reports[0]["summary"] == reports[1]["summary"]
    assert reports[0]["states"] == reports[1]["states"]
