import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from netops_auditor import cli
from netops_auditor import sarif
from netops_auditor.collect import ChannelEvent, CollectError, Snapshot
from netops_auditor.engine import CATALOG_DIR
from netops_auditor.store import Store
from netops_auditor.findings import fingerprint_of, fingerprint_v1
from netops_auditor.suppressions import FILE_VERSION as SUPPRESSION_FILE_VERSION
from netops_auditor.suppressions import SuppressionError, load_for_tenant
from netops_core.ssh import SshError, UNKNOWN_REASON, reason

FIXTURES = Path(__file__).parent / "fixtures"
CANARY = "KANARCI-RETEZEC-NESMI-UNIKNOUT"
TENANT = "tenant-a"
DEVICE = "fw-example"
WAN_RULE = "fortios.mgmt.wan-admin-access"
UTM_RULE = "fortios.policy.utm-without-ssl"


def clean_text():
    return (FIXTURES / "fortios_clean.conf").read_text(encoding="utf-8")


def mutate(text, old, new):
    assert text.count(old) == 1
    return text.replace(old, new)


def dirty_text():
    text = clean_text()
    text = mutate(
        text,
        "        set allowaccess ping\n",
        '        set allowaccess ping https ssh\n        set description "%s"\n' % CANARY,
    )
    text = mutate(text, '        set ssl-ssh-profile "certificate-inspection"\n', "")
    text = mutate(text, "        unset comments\n", '        set comments "%s"\n' % CANARY)
    text = mutate(text, 'set comment "site\nlocal network"', 'set comment "site\n%s\nlocal network"' % CANARY)
    return text


def write_config(directory, text, name="device.conf"):
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def run_args(path, as_json=False, store=None, tenant=TENANT, device=DEVICE, platform="fortios"):
    argv = ["run", "--platform", platform, "--tenant", tenant, "--device", device, "--config", str(path)]
    if store is not None:
        argv.extend(["--store", str(store)])
    if as_json:
        argv.append("--json")
    return argv


def invoke(capsys, argv):
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def audit(capsys, path, **kwargs):
    return invoke(capsys, run_args(path, **kwargs))


def config_lines(text, minimum=12):
    return tuple(sorted({line.strip() for line in text.splitlines() if len(line.strip()) >= minimum}))


def test_clean_configuration_reports_no_finding(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    code, out, err = audit(capsys, path, as_json=True)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["findings"] == []
    assert report["summary"]["total"] == 0
    assert report["tenant"] == TENANT
    assert report["device"] == DEVICE


def test_findings_do_not_change_the_exit_code(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    code, out, err = audit(capsys, path, as_json=True)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["summary"]["total"] == len(report["findings"])
    assert report["summary"]["total"] > 0
    assert sorted({item["rule_id"] for item in report["findings"]}) == [WAN_RULE, UTM_RULE]


def test_snapshot_sha256_is_the_digest_of_the_file_bytes(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    code, out, _ = audit(capsys, path, as_json=True)
    assert code == 0
    assert json.loads(out)["snapshot_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_rules_version_names_the_catalog(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    catalog = CATALOG_DIR / "fortios.json"
    expected = "fortios:%d:%s" % (
        len(json.loads(catalog.read_text(encoding="utf-8"))["rules"]),
        hashlib.sha256(catalog.read_bytes()).hexdigest(),
    )
    code, out, _ = audit(capsys, path, as_json=True)
    assert code == 0
    assert json.loads(out)["rules_version"] == expected


def test_unreadable_configuration_is_an_error(tmp_path, capsys):
    code, out, err = audit(capsys, tmp_path / "missing.conf")
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_broken_configuration_is_an_error(tmp_path, capsys):
    path = write_config(tmp_path, 'config system global\n    set hostname "fw"\n')
    code, out, err = audit(capsys, path)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_unknown_platform_is_rejected(tmp_path):
    path = write_config(tmp_path, clean_text())
    with pytest.raises(SystemExit) as failure:
        cli.main(run_args(path, platform="junos"))
    assert failure.value.code == 2


def test_report_does_not_carry_the_configuration(tmp_path, capsys):
    text = dirty_text()
    path = write_config(tmp_path, text)
    text_code, text_out, text_err = audit(capsys, path)
    json_code, json_out, json_err = audit(capsys, path, as_json=True)
    assert text_code == 0
    assert json_code == 0
    report = json.loads(json_out)
    assert report["summary"]["total"] > 0
    assert {item["object_key"] for item in report["findings"]} == {
        "system interface/wan1",
        "firewall policy/1",
    }
    for output in (text_out, text_err, json_out, json_err):
        assert CANARY not in output
    for line in config_lines(text):
        assert line not in text_out
        assert line not in json_out


def test_report_findings_carry_only_the_allowed_keys(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    code, out, _ = audit(capsys, path, as_json=True)
    assert code == 0
    findings = json.loads(out)["findings"]
    assert findings
    for item in findings:
        assert sorted(item) == sorted(cli.FINDING_KEYS)
        assert isinstance(item["evidence"], dict)


def test_text_report_names_every_finding(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    code, out, _ = audit(capsys, path)
    _, as_json, _ = audit(capsys, path, as_json=True)
    assert code == 0
    findings = json.loads(as_json)["findings"]
    assert findings
    for item in findings:
        assert item["rule_id"] in out
        assert item["object_key"] in out
        assert item["fingerprint"] in out


def test_output_is_byte_identical_for_the_same_input(tmp_path, capsys):
    text = dirty_text()
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir()
    right.mkdir()
    first = write_config(left, text, name="first.conf")
    second = write_config(right, text, name="second.conf")
    for as_json in (False, True):
        _, one, err_one = audit(capsys, first, as_json=as_json)
        _, two, err_two = audit(capsys, first, as_json=as_json)
        _, three, err_three = audit(capsys, second, as_json=as_json)
        assert one.encode("utf-8") == two.encode("utf-8")
        assert one.encode("utf-8") == three.encode("utf-8")
        assert err_one == err_two == err_three == ""


def test_store_records_the_run_and_its_findings(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    database = tmp_path / "audit.sqlite"
    code, out, err = audit(capsys, path, as_json=True, store=database)
    assert code == 0
    assert err == ""
    assert database.exists()
    report = json.loads(out)
    with Store(database) as store:
        recorded = store.last_run(TENANT, DEVICE)
        assert recorded is not None
        assert recorded["snapshot_sha256"] == report["snapshot_sha256"]
        assert recorded["snapshot_source"] == str(path)
        assert recorded["rules_version"] == report["rules_version"]
        stored = store.findings_for_run(TENANT, recorded["id"])
    assert [item["fingerprint"] for item in stored] == [item["fingerprint"] for item in report["findings"]]
    assert [item["rule_id"] for item in stored] == [item["rule_id"] for item in report["findings"]]
    assert [item["evidence"] for item in stored] == [item["evidence"] for item in report["findings"]]


def test_without_store_no_database_is_created(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    code, out, err = audit(capsys, path, as_json=True)
    assert code == 0
    assert err == ""
    assert out
    assert sorted(item.name for item in tmp_path.iterdir()) == ["device.conf"]


def test_store_failure_is_an_error_and_prints_no_report(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    database = tmp_path / "audit.sqlite"
    code, out, err = audit(capsys, path, as_json=True, store=database, tenant="   ")
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    with Store(database) as store:
        assert store.last_run("   ", DEVICE) is None


def test_store_in_a_missing_directory_is_an_error(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    code, out, err = audit(capsys, path, store=tmp_path / "nowhere" / "audit.sqlite")
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


WAN_OBJECT = "system interface/wan1"
UTM_OBJECT = "firewall policy/1"
ABSENT_OBJECT = "firewall policy/404"
CREATED = "2026-01-01T00:00:00Z"
EXPIRED = "2026-01-02T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"


def rule_version(rule_id):
    document = json.loads((CATALOG_DIR / "fortios.json").read_text(encoding="utf-8"))
    return {item["id"]: item["version"] for item in document["rules"]}[rule_id]


def suppression(rule_id, object_key, expires, reason="ticket NET-1", author="radek", device=DEVICE, tenant=TENANT):
    version = rule_version(rule_id)
    return {
        "fingerprint": fingerprint_of(rule_id, version, tenant, device, object_key),
        "rule_id": rule_id,
        "rule_version": version,
        "device": device,
        "object_key": object_key,
        "reason": reason,
        "author": author,
        "created": CREATED,
        "expires": expires,
    }


def write_suppressions(directory, items, name="suppressions.json", tenant=TENANT, version=SUPPRESSION_FILE_VERSION):
    document = {"version": version, "suppressions": items}
    if tenant is not None:
        document["tenant"] = tenant
    path = directory / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def write_v1_suppressions(directory, items, name="v1.json"):
    document = {"version": 1, "suppressions": items}
    path = directory / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def v1_suppression(rule_id, object_key, expires, reason="ticket NET-1", author="radek", device=DEVICE):
    version = rule_version(rule_id)
    return {
        "fingerprint": fingerprint_v1(rule_id, version, device, object_key),
        "rule_id": rule_id,
        "rule_version": version,
        "device": device,
        "object_key": object_key,
        "reason": reason,
        "author": author,
        "created": CREATED,
        "expires": expires,
    }


def full_args(path, store=None, as_json=False, suppressions=None, accept=None, tenant=TENANT, device=DEVICE):
    argv = run_args(path, as_json=as_json, store=store, tenant=tenant, device=device)
    if suppressions is not None:
        argv.extend(["--suppressions", str(suppressions)])
    if accept is not None:
        argv.extend(["--baseline-accept", "--accepted-by", accept[0], "--note", accept[1]])
    return argv


def status_args(store, tenant=TENANT, device=DEVICE, hours=None, as_json=False):
    argv = ["status", "--tenant", tenant, "--device", device, "--store", str(store)]
    if hours is not None:
        argv.extend(["--stale-after-hours", str(hours)])
    if as_json:
        argv.append("--json")
    return argv


def states_by_rule(report):
    return {item["rule_id"]: item["state"] for item in report["findings"]}


def moment(hours_ago):
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_run(database, started_at, tenant=TENANT, device=DEVICE):
    with Store(database) as store:
        store.record_run(tenant, device, "0" * 64, "seed.conf", "fortios:0:seed", (), started_at=started_at)


def test_report_groups_the_findings_by_state(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    code, out, err = invoke(capsys, full_args(path, as_json=True))
    text_code, text_out, _ = invoke(capsys, full_args(path))
    assert code == 0
    assert text_code == 0
    assert err == ""
    report = json.loads(out)
    total = report["summary"]["total"]
    assert total > 0
    assert report["states"] == {"new": total, "open-known": 0, "suppressed": 0, "gone": 0}
    assert {item["state"] for item in report["findings"]} == {"new"}
    assert report["gone"] == []
    assert report["suppressions"] == {"orphaned": [], "expired": []}
    assert "states: new %d, open-known 0, suppressed 0, gone 0" % total in text_out
    assert "state new: %d" % total in text_out
    assert "state open-known: 0" in text_out
    assert "state suppressed: 0" in text_out
    assert "state gone: 0" in text_out


def test_open_known_stays_visible_and_apart_from_suppressed(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    database = tmp_path / "audit.sqlite"
    first_code, first_out, first_err = invoke(
        capsys, full_args(path, store=database, as_json=True, accept=("radek", "prevzato pri nasazeni"))
    )
    assert first_code == 0
    first = json.loads(first_out)
    total = first["summary"]["total"]
    assert first["states"]["new"] == total
    assert first_err == "baseline: accepted %d of %d findings\n" % (total, total)
    code, out, err = invoke(capsys, full_args(path, store=database, as_json=True))
    text_code, text_out, _ = invoke(capsys, full_args(path, store=database))
    assert code == 0
    assert text_code == 0
    assert err == ""
    report = json.loads(out)
    assert report["states"] == {"new": 0, "open-known": total, "suppressed": 0, "gone": 0}
    assert {item["state"] for item in report["findings"]} == {"open-known"}
    assert "state open-known: %d" % total in text_out
    assert "state suppressed: 0" in text_out
    for item in report["findings"]:
        assert item["rule_id"] in text_out
        assert item["object_key"] in text_out
        assert item["fingerprint"] in text_out


def test_finding_entries_carry_the_state_key(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    code, out, _ = invoke(capsys, full_args(path, as_json=True))
    assert code == 0
    assert "state" in cli.FINDING_KEYS
    for item in json.loads(out)["findings"]:
        assert sorted(item) == sorted(cli.FINDING_KEYS)
        assert item["state"] in ("new", "open-known", "suppressed")


def test_baseline_accept_records_who_and_why(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    database = tmp_path / "audit.sqlite"
    code, out, _ = invoke(capsys, full_args(path, store=database, as_json=True, accept=("radek", "prevzato")))
    assert code == 0
    report = json.loads(out)
    with Store(database) as store:
        entries = store.baseline_entries(TENANT, DEVICE)
    assert [item["fingerprint"] for item in entries] == [item["fingerprint"] for item in report["findings"]]
    assert {item["accepted_by"] for item in entries} == {"radek"}
    assert {item["note"] for item in entries} == {"prevzato"}


def test_baseline_accept_without_store_is_an_error(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    code, out, err = invoke(capsys, full_args(path, accept=("radek", "prevzato")))
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_baseline_accept_without_author_or_note_is_an_error(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    database = tmp_path / "audit.sqlite"
    for extra in (["--accepted-by", "radek"], ["--note", "prevzato"], []):
        argv = run_args(path, store=database) + ["--baseline-accept"] + extra
        code, out, err = invoke(capsys, argv)
        assert code == 2
        assert out == ""
        assert err.startswith("error: ")
    assert not database.exists()


def test_author_and_note_without_baseline_accept_are_an_error(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    argv = run_args(path) + ["--accepted-by", "radek", "--note", "prevzato"]
    code, out, err = invoke(capsys, argv)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_gone_appears_after_the_finding_disappears(tmp_path, capsys):
    dirty = write_config(tmp_path, dirty_text(), name="dirty.conf")
    clean = write_config(tmp_path, clean_text(), name="clean.conf")
    json_store = tmp_path / "json.sqlite"
    text_store = tmp_path / "text.sqlite"
    _, first_out, _ = invoke(capsys, full_args(dirty, store=json_store, as_json=True))
    invoke(capsys, full_args(dirty, store=text_store))
    first = json.loads(first_out)
    assert first["states"]["gone"] == 0
    code, out, _ = invoke(capsys, full_args(clean, store=json_store, as_json=True))
    text_code, text_out, _ = invoke(capsys, full_args(clean, store=text_store))
    assert code == 0
    assert text_code == 0
    report = json.loads(out)
    assert report["summary"]["total"] == 0
    assert report["states"]["gone"] == first["summary"]["total"]
    assert [item["fingerprint"] for item in report["gone"]] == [item["fingerprint"] for item in first["findings"]]
    assert [item["rule_id"] for item in report["gone"]] == [item["rule_id"] for item in first["findings"]]
    assert "state gone: %d" % first["summary"]["total"] in text_out
    for item in report["gone"]:
        assert sorted(item) == sorted(cli.GONE_KEYS)
        assert item["fingerprint"] in text_out
        assert item["rule_id"] in text_out


def test_without_store_nothing_is_gone(tmp_path, capsys):
    dirty = write_config(tmp_path, dirty_text(), name="dirty.conf")
    clean = write_config(tmp_path, clean_text(), name="clean.conf")
    invoke(capsys, full_args(dirty))
    code, out, _ = invoke(capsys, full_args(clean, as_json=True))
    assert code == 0
    report = json.loads(out)
    assert report["gone"] == []
    assert report["states"]["gone"] == 0


def test_active_suppression_takes_the_finding_out_of_new(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    waivers = write_suppressions(tmp_path, [suppression(WAN_RULE, WAN_OBJECT, FUTURE)])
    code, out, err = invoke(capsys, full_args(path, as_json=True, suppressions=waivers))
    text_code, text_out, _ = invoke(capsys, full_args(path, suppressions=waivers))
    assert code == 0
    assert text_code == 0
    assert err == ""
    report = json.loads(out)
    states = states_by_rule(report)
    assert states[WAN_RULE] == "suppressed"
    assert states[UTM_RULE] == "new"
    assert report["states"]["suppressed"] == 1
    assert report["suppressions"] == {"orphaned": [], "expired": []}
    assert "state suppressed: 1" in text_out


def test_broken_suppression_file_stops_the_run(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    database = tmp_path / "audit.sqlite"
    broken = tmp_path / "broken.json"
    broken.write_text(
        json.dumps(
            {
                "version": SUPPRESSION_FILE_VERSION,
                "tenant": TENANT,
                "suppressions": [{"rule_id": WAN_RULE}],
            }
        ),
        encoding="utf-8",
    )
    code, out, err = invoke(capsys, full_args(path, as_json=True, store=database, suppressions=broken))
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert not database.exists()


def test_missing_suppression_file_stops_the_run(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    code, out, err = invoke(capsys, full_args(path, suppressions=tmp_path / "nowhere.json"))
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_a_suppression_file_bound_to_another_tenant_is_refused_naming_both(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    waivers = write_suppressions(
        tmp_path,
        [suppression(WAN_RULE, WAN_OBJECT, FUTURE, tenant="tenant-b")],
        tenant="tenant-b",
    )
    code, out, err = invoke(capsys, full_args(path, as_json=True, suppressions=waivers))
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert TENANT in err
    assert "tenant-b" in err


def test_a_suppression_file_without_a_tenant_is_refused_and_names_the_migration(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    waivers = write_suppressions(
        tmp_path, [suppression(WAN_RULE, WAN_OBJECT, FUTURE)], tenant=None,
    )
    code, out, err = invoke(capsys, full_args(path, as_json=True, suppressions=waivers))
    assert code == 2
    assert out == ""
    assert "missing document fields: tenant" in err
    assert "migrate-suppressions" in err


def test_a_version_1_suppression_file_is_refused_and_names_the_migration(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    waivers = write_v1_suppressions(tmp_path, [v1_suppression(WAN_RULE, WAN_OBJECT, FUTURE)])
    code, out, err = invoke(capsys, full_args(path, as_json=True, suppressions=waivers))
    assert code == 2
    assert out == ""
    assert "version 1 is refused" in err
    assert "migrate-suppressions" in err


def test_a_suppression_file_bound_to_the_running_tenant_works_with_no_notice(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    waivers = write_suppressions(
        tmp_path, [suppression(WAN_RULE, WAN_OBJECT, FUTURE)], tenant=TENANT,
    )
    code, out, err = invoke(capsys, full_args(path, as_json=True, suppressions=waivers))
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert states_by_rule(report)[WAN_RULE] == "suppressed"


def test_orphaned_and_expired_suppressions_are_named_in_the_report(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    orphan = suppression(UTM_RULE, ABSENT_OBJECT, FUTURE, reason="ticket NET-2", author="petr")
    stale = suppression(WAN_RULE, WAN_OBJECT, EXPIRED, reason="ticket NET-3", author="radek")
    waivers = write_suppressions(tmp_path, [orphan, stale])
    code, out, _ = invoke(capsys, full_args(path, as_json=True, suppressions=waivers))
    text_code, text_out, _ = invoke(capsys, full_args(path, suppressions=waivers))
    assert code == 0
    assert text_code == 0
    report = json.loads(out)
    assert [item["fingerprint"] for item in report["suppressions"]["orphaned"]] == [orphan["fingerprint"]]
    assert [item["fingerprint"] for item in report["suppressions"]["expired"]] == [stale["fingerprint"]]
    assert states_by_rule(report)[WAN_RULE] == "new"
    assert report["states"]["suppressed"] == 0
    assert "orphaned suppressions: 1" in text_out
    assert "expired suppressions: 1" in text_out
    for item in report["suppressions"]["orphaned"] + report["suppressions"]["expired"]:
        assert sorted(item) == sorted(cli.SUPPRESSION_KEYS)
        for key in cli.SUPPRESSION_KEYS:
            assert item[key] in text_out


def test_report_stays_byte_identical_with_states_and_suppressions(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    waivers = write_suppressions(
        tmp_path,
        [suppression(WAN_RULE, WAN_OBJECT, FUTURE), suppression(UTM_RULE, ABSENT_OBJECT, EXPIRED)],
    )
    database = tmp_path / "audit.sqlite"
    for as_json in (False, True):
        _, one, err_one = invoke(capsys, full_args(path, as_json=as_json, store=database, suppressions=waivers))
        _, two, err_two = invoke(capsys, full_args(path, as_json=as_json, store=database, suppressions=waivers))
        _, three, err_three = invoke(capsys, full_args(path, as_json=as_json, store=database, suppressions=waivers))
        assert one.encode("utf-8") == two.encode("utf-8")
        assert one.encode("utf-8") == three.encode("utf-8")
        assert err_one == err_two == err_three == ""


def test_states_and_suppressions_do_not_carry_the_configuration(tmp_path, capsys):
    text = dirty_text()
    dirty = write_config(tmp_path, text, name="dirty.conf")
    clean = write_config(tmp_path, clean_text(), name="clean.conf")
    waivers = write_suppressions(
        tmp_path,
        [
            suppression(WAN_RULE, WAN_OBJECT, FUTURE, reason="ticket NET-1", author="radek"),
            suppression(UTM_RULE, ABSENT_OBJECT, EXPIRED, reason="ticket NET-2", author="petr"),
        ],
    )
    json_store = tmp_path / "json.sqlite"
    text_store = tmp_path / "text.sqlite"
    invoke(capsys, full_args(dirty, store=json_store, as_json=True, accept=("radek", "prevzato")))
    invoke(capsys, full_args(dirty, store=text_store, accept=("radek", "prevzato")))
    known_json = invoke(capsys, full_args(dirty, store=json_store, as_json=True, suppressions=waivers))
    known_text = invoke(capsys, full_args(dirty, store=text_store, suppressions=waivers))
    gone_json = invoke(capsys, full_args(clean, store=json_store, as_json=True, suppressions=waivers))
    gone_text = invoke(capsys, full_args(clean, store=text_store, suppressions=waivers))
    known = json.loads(known_json[1])
    gone = json.loads(gone_json[1])
    assert known["states"]["open-known"] > 0
    assert known["states"]["suppressed"] > 0
    assert gone["states"]["gone"] > 0
    assert gone["suppressions"]["orphaned"] and gone["suppressions"]["expired"]
    for result in (known_json, known_text, gone_json, gone_text):
        assert result[0] == 0
        assert CANARY not in result[1]
        assert CANARY not in result[2]
        for line in config_lines(text):
            assert line not in result[1]


def test_status_is_fresh_right_after_a_run(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    database = tmp_path / "audit.sqlite"
    invoke(capsys, full_args(path, store=database))
    code, out, err = invoke(capsys, status_args(database, as_json=True))
    text_code, text_out, _ = invoke(capsys, status_args(database))
    assert code == 0
    assert text_code == 0
    assert err == ""
    report = json.loads(out)
    assert report["state"] == "fresh"
    assert report["age_hours"] < 1
    assert report["stale_after_hours"] == cli.DEFAULT_STALE_AFTER_HOURS
    with Store(database) as store:
        assert report["last_audit"] == store.last_run(TENANT, DEVICE)["started_at"]
    assert "state: fresh" in text_out
    assert report["last_audit"] in text_out


def test_status_is_stale_when_the_last_run_is_old(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    old = moment(30)
    seed_run(database, old)
    code, out, err = invoke(capsys, status_args(database, as_json=True))
    text_code, text_out, _ = invoke(capsys, status_args(database))
    assert code == 1
    assert text_code == 1
    assert err == ""
    report = json.loads(out)
    assert report["state"] == "stale"
    assert report["last_audit"] == old
    assert 29 < report["age_hours"] < 31
    assert "state: stale" in text_out


def test_status_threshold_decides_what_is_stale(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    seed_run(database, moment(3))
    fresh_code, fresh_out, _ = invoke(capsys, status_args(database, hours=26, as_json=True))
    stale_code, stale_out, _ = invoke(capsys, status_args(database, hours=2, as_json=True))
    assert fresh_code == 0
    assert json.loads(fresh_out)["state"] == "fresh"
    assert stale_code == 1
    assert json.loads(stale_out)["state"] == "stale"
    assert json.loads(stale_out)["stale_after_hours"] == 2


def test_status_of_a_device_that_was_never_audited_is_a_finding(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    database = tmp_path / "audit.sqlite"
    invoke(capsys, full_args(path, store=database))
    code, out, err = invoke(capsys, status_args(database, device="fw-other", as_json=True))
    text_code, text_out, _ = invoke(capsys, status_args(database, device="fw-other"))
    assert code == 1
    assert text_code == 1
    assert err == ""
    report = json.loads(out)
    assert report["state"] == "never"
    assert report["last_audit"] is None
    assert report["age_hours"] is None
    assert "state: never" in text_out
    assert "fw-other" in text_out


def test_status_of_an_unknown_tenant_is_a_finding(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    database = tmp_path / "audit.sqlite"
    invoke(capsys, full_args(path, store=database))
    code, out, err = invoke(capsys, status_args(database, tenant="tenant-b", as_json=True))
    assert code == 1
    assert err == ""
    assert json.loads(out)["state"] == "never"


def test_status_needs_an_existing_store(tmp_path, capsys):
    database = tmp_path / "missing.sqlite"
    code, out, err = invoke(capsys, status_args(database))
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert not database.exists()


def test_status_requires_the_store_option(tmp_path):
    with pytest.raises(SystemExit) as failure:
        cli.main(["status", "--tenant", TENANT, "--device", DEVICE])
    assert failure.value.code == 2


def test_status_rejects_a_threshold_that_is_not_positive(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    seed_run(database, moment(1))
    for hours in (0, -1):
        code, out, err = invoke(capsys, status_args(database, hours=hours))
        assert code == 2
        assert out == ""
        assert err.startswith("error: ")


CANARY_TOKEN = "KANARCI-TOKEN-NESMI-UNIKNOUT"
KEY_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
KEY_FOOTER = "-----END " + "OPENSSH PRIVATE KEY-----"
CANARY_KEY = "%s\nKANARCI-KLIC-NESMI-UNIKNOUT\n%s\n" % (KEY_HEADER, KEY_FOOTER)
CANARY_STDERR = "KANARCI-STDERR-ZARIZENI-NESMI-UNIKNOUT"
CREDENTIAL_NAME = "fw-example-audit-ro"
REST_HOST = "192.0.2.10"
SSH_HOST = "198.51.100.10"
SSH_PORT = 22
LOGIN = "audit-ro"
TLS_FINGERPRINT = "0123456789abcdef" * 4
HOST_KEY = "SHA256:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
SECTIONS = ("system global", "system interface", "firewall policy")
MISSING_SECTION = "vpn ipsec phase1-interface"
INCOMPLETE_RULE = "fortios.snapshot.incomplete"
MOMENT_AT = "2026-01-01T00:00:00Z"
KEPT = object()


def device_item(
    channel="file",
    source="/var/lib/netops/fw-example.conf",
    credential=None,
    sections=SECTIONS,
    platform="fortios",
    name=DEVICE,
    address=None,
    port=None,
    tls_fingerprint=None,
    host_key_fingerprint=None,
    legacy_ssh=None,
    auditor=KEPT,
):
    section = {
        "channel": channel,
        "source": None if source is None else str(source),
        "required_sections": list(sections),
        "tls_fingerprint": tls_fingerprint,
    }
    return {
        "name": name,
        "platform": platform,
        "address": address,
        "port": port,
        "role": "perimetr",
        "credential": credential,
        "host_key_fingerprint": host_key_fingerprint,
        "legacy_ssh": legacy_ssh,
        "auditor": section if auditor is KEPT else auditor,
        "helper": None,
    }


def rest_item(**kwargs):
    return device_item(
        channel="fortios-rest",
        source="https://%s" % REST_HOST,
        credential=CREDENTIAL_NAME,
        tls_fingerprint=TLS_FINGERPRINT,
        **kwargs
    )


def ssh_item(**kwargs):
    return device_item(
        channel="ssh",
        source=None,
        address=SSH_HOST,
        port=SSH_PORT,
        credential=CREDENTIAL_NAME,
        host_key_fingerprint=HOST_KEY,
        **kwargs
    )


def write_inventory(directory, items, name="inventory.json"):
    path = directory / name
    path.write_text(json.dumps({"version": 2, "devices": list(items)}), encoding="utf-8")
    return path


def file_inventory(directory, config, sections=SECTIONS, name="inventory.json"):
    return write_inventory(directory, [device_item(source=config, sections=sections)], name=name)


def write_vault(
    directory,
    value=CANARY_TOKEN,
    name="vault.json",
    kind="api-token",
    login=None,
    version=2,
    credential=CREDENTIAL_NAME,
):
    entry = {"kind": kind, "value": value}
    if login is not None:
        entry["login"] = login
    path = directory / name
    path.write_text(
        json.dumps({"version": version, "credentials": {credential: entry}}), encoding="utf-8"
    )
    os.chmod(path, 0o600)
    return path


def write_ssh_vault(directory, value=CANARY_KEY, kind="ssh-key", **kwargs):
    return write_vault(directory, value=value, kind=kind, login=LOGIN, **kwargs)


def collect_args(
    inventory_path,
    tenant=TENANT,
    device=DEVICE,
    store=None,
    vault_path=None,
    suppressions=None,
    as_json=False,
    accept=None,
):
    argv = ["collect", "--inventory", str(inventory_path), "--device", device, "--tenant", tenant]
    if store is not None:
        argv.extend(["--store", str(store)])
    if vault_path is not None:
        argv.extend(["--vault", str(vault_path)])
    if suppressions is not None:
        argv.extend(["--suppressions", str(suppressions)])
    if accept is not None:
        argv.extend(["--baseline-accept", "--accepted-by", accept[0], "--note", accept[1]])
    if as_json:
        argv.append("--json")
    return argv


def gather(capsys, inventory_path, **kwargs):
    return invoke(capsys, collect_args(inventory_path, **kwargs))


def database_text(path):
    connection = sqlite3.connect(str(path))
    try:
        tables = [
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        ]
        chunks = list(tables)
        for table in tables:
            cursor = connection.execute("SELECT * FROM %s" % table)
            chunks.extend(column[0] for column in cursor.description)
            for row in cursor.fetchall():
                chunks.extend(str(value) for value in row)
    finally:
        connection.close()
    return "\n".join(chunks)


def snapshot_of(text, channel, source, profile, platform="fortios"):
    data = text.encode("utf-8")
    return Snapshot(
        device=DEVICE,
        platform=platform,
        channel=channel,
        source=source,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        collected_at=MOMENT_AT,
        profile=profile,
        text=text,
    )


def event_of(snapshot, request, outcome="ok"):
    return ChannelEvent(
        device=snapshot.device,
        channel=snapshot.channel,
        request=request,
        response_sha256=snapshot.sha256,
        response_bytes=snapshot.size_bytes,
        started_at=MOMENT_AT,
        finished_at=MOMENT_AT,
        outcome=outcome,
    )


def step_event(channel, request, outcome="ok"):
    return ChannelEvent(
        device=DEVICE,
        channel=channel,
        request=request,
        response_sha256="0" * 64,
        response_bytes=0,
        started_at=MOMENT_AT,
        finished_at=MOMENT_AT,
        outcome=outcome,
    )


def test_collect_over_the_file_channel_reports_what_run_reports(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    inventory_path = file_inventory(tmp_path, path)
    code, out, err = gather(capsys, inventory_path, as_json=True)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    audited = json.loads(audit(capsys, path, as_json=True)[1])
    assert [item["fingerprint"] for item in report["findings"]] == [
        item["fingerprint"] for item in audited["findings"]
    ]
    assert sorted({item["rule_id"] for item in report["findings"]}) == [WAN_RULE, UTM_RULE]
    assert report["snapshot_sha256"] == audited["snapshot_sha256"]
    assert report["rules_version"] == audited["rules_version"]
    assert report["states"] == audited["states"]
    assert report["gone"] == []
    assert report["suppressions"] == {"orphaned": [], "expired": []}
    for item in report["findings"]:
        assert sorted(item) == sorted(cli.FINDING_KEYS)


def test_collect_report_carries_the_collection_header(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    inventory_path = file_inventory(tmp_path, path)
    code, out, _ = gather(capsys, inventory_path, as_json=True)
    assert code == 0
    report = json.loads(out)
    assert sorted(report["collection"]) == sorted(cli.COLLECTION_KEYS)
    assert report["collection"] == {
        "channel": "file",
        "source": str(path),
        "profile": cli.DEFAULT_PROFILE,
        "credential-kind": cli.CREDENTIAL_NONE,
        "snapshot_sha256": report["snapshot_sha256"],
        "legacy_ssh": cli.LEGACY_NONE,
    }
    text_code, text_out, _ = gather(capsys, inventory_path)
    assert text_code == 0
    assert "collection-channel: file" in text_out
    assert "collection-source: %s" % path in text_out
    assert "collection-profile: %s" % cli.DEFAULT_PROFILE in text_out
    assert "collection-credential-kind: %s" % cli.CREDENTIAL_NONE in text_out
    assert "collection-snapshot_sha256: %s" % report["snapshot_sha256"] in text_out
    assert "collection-legacy_ssh: %s" % cli.LEGACY_NONE in text_out


def test_collect_over_a_channel_without_a_login_reports_the_default_profile(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    inventory_path = file_inventory(tmp_path, path)
    code, out, _ = gather(capsys, inventory_path, as_json=True)
    assert code == 0
    assert json.loads(out)["collection"]["profile"] == cli.DEFAULT_PROFILE


def test_incomplete_view_is_the_only_finding(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    narrow = file_inventory(
        tmp_path, path, sections=SECTIONS + (MISSING_SECTION,), name="narrow.json"
    )
    code, out, err = gather(capsys, narrow, as_json=True)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert [item["rule_id"] for item in report["findings"]] == [INCOMPLETE_RULE]
    assert report["summary"]["total"] == 1
    assert report["summary"]["high"] == 1
    assert report["findings"][0]["severity"] == "high"
    assert report["findings"][0]["section"] == "snapshot"
    assert report["findings"][0]["evidence"] == {
        "missing_count": 1,
        "missing_sections": MISSING_SECTION,
    }
    assert WAN_RULE not in out
    assert UTM_RULE not in out
    _, text_out, _ = gather(capsys, narrow)
    assert WAN_RULE not in text_out
    assert UTM_RULE not in text_out


def test_a_section_written_with_its_header_is_an_error_not_a_finding(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    prefixed = file_inventory(
        tmp_path, path, sections=("config system global",), name="prefixed.json"
    )
    code, out, err = gather(capsys, prefixed, as_json=True)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert "completeness:" in err
    assert "'config system global'" in err
    assert "'system global'" in err
    assert INCOMPLETE_RULE not in err


def test_completeness_measures_a_snapshot_with_the_platform_it_carries(tmp_path):
    path = write_inventory(
        tmp_path, [device_item(platform="exos", sections=("vlan",))], name="exos.json"
    )
    record, section = cli._inventory_record(path, DEVICE)
    text = "#\n# Module vlan configuration.\n#\nconfigure vlan Mgmt tag 10\n"
    snapshot = snapshot_of(text, "file", str(path), cli.DEFAULT_PROFILE, platform="exos")
    assert cli._completeness(TENANT, record, section, snapshot) is None


def test_a_complete_view_lets_the_other_rules_run(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    inventory_path = file_inventory(tmp_path, path)
    code, out, _ = gather(capsys, inventory_path, as_json=True)
    assert code == 0
    report = json.loads(out)
    assert sorted({item["rule_id"] for item in report["findings"]}) == [WAN_RULE, UTM_RULE]
    assert INCOMPLETE_RULE not in out


def test_incomplete_view_is_recorded_alone(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    narrow = file_inventory(
        tmp_path, path, sections=SECTIONS + (MISSING_SECTION,), name="narrow.json"
    )
    database = tmp_path / "audit.sqlite"
    code, _, err = gather(capsys, narrow, as_json=True, store=database)
    assert code == 0
    assert err == ""
    with Store(database) as store:
        recorded = store.last_run(TENANT, DEVICE)
        stored = store.findings_for_run(TENANT, recorded["id"])
    assert [item["rule_id"] for item in stored] == [INCOMPLETE_RULE]


def test_failed_collection_leaves_the_channel_event_behind(tmp_path, capsys):
    missing = tmp_path / "nowhere.conf"
    inventory_path = file_inventory(tmp_path, missing)
    database = tmp_path / "audit.sqlite"
    code, out, err = gather(capsys, inventory_path, store=database)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert database.exists()
    with Store(database) as store:
        assert store.last_run(TENANT, DEVICE) is None
        assert store.runs_for_device(TENANT, DEVICE) == ()
        events = store.channel_events(TENANT, DEVICE)
    assert len(events) == 1
    assert events[0]["outcome"] == "failed"
    assert events[0]["run_id"] is None
    assert events[0]["channel"] == "file"
    assert events[0]["request"] == str(missing)


def test_failed_collection_without_store_writes_nothing(tmp_path, capsys):
    missing = tmp_path / "nowhere.conf"
    inventory_path = file_inventory(tmp_path, missing)
    code, out, err = gather(capsys, inventory_path)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert sorted(item.name for item in tmp_path.iterdir()) == ["inventory.json"]


def test_credential_never_reaches_the_output_or_the_store(tmp_path, capsys, monkeypatch):
    text = dirty_text()
    inventory_path = write_inventory(tmp_path, [rest_item()])
    vault_path = write_vault(tmp_path)
    database = tmp_path / "audit.sqlite"
    seen = {}

    def fake(device, host, credential, profile, tls_fingerprint=None, **rest):
        seen["token"] = credential.use()
        snapshot = snapshot_of(text, "fortios-rest", host, profile)
        return snapshot, event_of(snapshot, "POST %s/api/v2/monitor" % host)

    monkeypatch.setattr(cli.collect, "collect_fortios_rest", fake)
    code, out, err = gather(
        capsys,
        inventory_path,
        as_json=True,
        store=database,
        vault_path=vault_path,
    )
    assert code == 0
    assert err == ""
    assert seen["token"] == CANARY_TOKEN
    report = json.loads(out)
    assert report["summary"]["total"] > 0
    _, text_out, text_err = gather(
        capsys, inventory_path, store=database, vault_path=vault_path
    )
    for output in (out, err, text_out, text_err):
        assert CANARY_TOKEN not in output
    assert CANARY_TOKEN not in database_text(database)


def test_credential_never_reaches_the_trace_of_a_failed_collection(tmp_path, capsys, monkeypatch):
    inventory_path = write_inventory(tmp_path, [rest_item()])
    vault_path = write_vault(tmp_path)
    database = tmp_path / "audit.sqlite"
    seen = {}

    def fake(device, host, credential, profile, tls_fingerprint=None, **rest):
        seen["token"] = credential.use()
        raise CollectError(
            "POST %s failed (TimeoutError)" % host,
            step_event("fortios-rest", "POST %s/api/v2/monitor" % host, outcome="failed"),
        )

    monkeypatch.setattr(cli.collect, "collect_fortios_rest", fake)
    code, out, err = gather(
        capsys,
        inventory_path,
        as_json=True,
        store=database,
        vault_path=vault_path,
    )
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert seen["token"] == CANARY_TOKEN
    assert CANARY_TOKEN not in err
    assert CANARY_TOKEN not in database_text(database)
    with Store(database) as store:
        assert store.last_run(TENANT, DEVICE) is None
        events = store.channel_events(TENANT, DEVICE)
    assert len(events) == 1
    assert events[0]["outcome"] == "failed"
    assert events[0]["run_id"] is None


def test_a_devices_own_stderr_never_reaches_the_trace_of_a_failed_collection(
    tmp_path, capsys, monkeypatch
):
    inventory_path = write_inventory(tmp_path, [ssh_item()])
    vault_path = write_ssh_vault(tmp_path)
    database = tmp_path / "audit.sqlite"

    def fake(device, platform, address, port, credential, host_key_fingerprint, **rest):
        source = "%s@%s" % (credential.login, address)
        request = "%s show" % source
        classified = reason(CANARY_STDERR)
        error = SshError(
            "ssh to %s failed with exit code 255; %s" % (address, classified),
            255,
            CANARY_STDERR,
        )
        raise CollectError(
            "%s: %s" % (request, error), step_event("ssh", request, outcome="failed"),
        )

    monkeypatch.setattr(cli.collect, "collect_ssh", fake)
    code, out, err = gather(
        capsys,
        inventory_path,
        as_json=True,
        store=database,
        vault_path=vault_path,
    )
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert UNKNOWN_REASON in err
    assert CANARY_STDERR not in out
    assert CANARY_STDERR not in err
    assert CANARY_STDERR not in database_text(database)
    with Store(database) as store:
        assert store.last_run(TENANT, DEVICE) is None
        events = store.channel_events(TENANT, DEVICE)
    assert len(events) == 1
    assert events[0]["outcome"] == "failed"
    assert events[0]["run_id"] is None


def test_a_device_with_a_credential_needs_the_vault(tmp_path, capsys):
    inventory_path = write_inventory(tmp_path, [rest_item()])
    code, out, err = gather(capsys, inventory_path)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert "--vault" in err


def test_a_vault_the_file_channel_does_not_need_is_an_error(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    inventory_path = file_inventory(tmp_path, path)
    vault_path = write_vault(tmp_path)
    code, out, err = gather(capsys, inventory_path, vault_path=vault_path)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert "--vault" in err


def test_an_unknown_credential_name_is_an_error(tmp_path, capsys):
    inventory_path = write_inventory(tmp_path, [rest_item()])
    vault_path = write_vault(tmp_path, credential="other")
    code, out, err = gather(capsys, inventory_path, vault_path=vault_path)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
    assert CREDENTIAL_NAME in err


def test_a_version_1_vault_is_refused(tmp_path, capsys):
    inventory_path = write_inventory(tmp_path, [rest_item()])
    vault_path = write_vault(tmp_path, version=1)
    code, out, err = gather(capsys, inventory_path, vault_path=vault_path)
    assert code == 2
    assert out == ""
    assert "vault: " in err
    assert "version must be 2" in err
    assert CANARY_TOKEN not in err


def test_the_rest_channel_refuses_a_credential_of_another_kind(tmp_path, capsys, monkeypatch):
    inventory_path = write_inventory(tmp_path, [rest_item()])
    vault_path = write_vault(tmp_path, value="replace-me", kind="password", login=LOGIN)
    called = []

    monkeypatch.setattr(cli.collect, "collect_fortios_rest", lambda *a, **k: called.append(a))
    code, out, err = gather(capsys, inventory_path, vault_path=vault_path)
    assert code == 2
    assert out == ""
    assert "of kind password" in err
    assert "kind api-token" in err
    assert called == []


def test_the_ssh_channel_refuses_a_credential_of_another_kind(tmp_path, capsys, monkeypatch):
    inventory_path = write_inventory(tmp_path, [ssh_item()])
    vault_path = write_vault(tmp_path)
    called = []

    monkeypatch.setattr(cli.collect, "collect_ssh", lambda *a, **k: called.append(a))
    code, out, err = gather(capsys, inventory_path, vault_path=vault_path)
    assert code == 2
    assert out == ""
    assert "of kind api-token" in err
    assert "kind password or ssh-key" in err
    assert called == []


def test_store_never_holds_the_configuration(tmp_path, capsys):
    text = dirty_text()
    path = write_config(tmp_path, text)
    inventory_path = file_inventory(tmp_path, path)
    database = tmp_path / "audit.sqlite"
    code, out, err = gather(capsys, inventory_path, as_json=True, store=database)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["summary"]["total"] > 0
    dumped = database_text(database)
    assert CANARY not in dumped
    for line in config_lines(text):
        assert line not in dumped
    with Store(database) as store:
        recorded = store.last_run(TENANT, DEVICE)
    assert recorded["snapshot_sha256"] == report["snapshot_sha256"]
    assert recorded["snapshot_source"] == str(path)


def test_collect_report_does_not_carry_the_configuration(tmp_path, capsys):
    text = dirty_text()
    path = write_config(tmp_path, text)
    inventory_path = file_inventory(tmp_path, path)
    text_code, text_out, text_err = gather(capsys, inventory_path)
    json_code, json_out, json_err = gather(capsys, inventory_path, as_json=True)
    assert text_code == 0
    assert json_code == 0
    for output in (text_out, text_err, json_out, json_err):
        assert CANARY not in output
    for line in config_lines(text):
        assert line not in text_out
        assert line not in json_out


def test_collect_without_store_writes_nothing_and_nothing_is_gone(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    inventory_path = file_inventory(tmp_path, path)
    code, out, err = gather(capsys, inventory_path, as_json=True)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["gone"] == []
    assert report["states"]["gone"] == 0
    assert report["states"]["open-known"] == 0
    assert sorted(item.name for item in tmp_path.iterdir()) == ["device.conf", "inventory.json"]


def test_store_ties_the_channel_event_to_the_run(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    inventory_path = file_inventory(tmp_path, path)
    database = tmp_path / "audit.sqlite"
    code, out, err = gather(capsys, inventory_path, as_json=True, store=database)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    with Store(database) as store:
        recorded = store.last_run(TENANT, DEVICE)
        stored = store.findings_for_run(TENANT, recorded["id"])
        events = store.channel_events_for_run(TENANT, recorded["id"])
    assert [item["fingerprint"] for item in stored] == [
        item["fingerprint"] for item in report["findings"]
    ]
    assert len(events) == 1
    assert events[0]["outcome"] == "ok"
    assert events[0]["run_id"] == recorded["id"]
    assert events[0]["response_sha256"] == report["snapshot_sha256"]


def test_collect_marks_a_finding_gone_after_it_disappears(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    dirty = write_config(tmp_path, dirty_text(), name="dirty.conf")
    clean = write_config(tmp_path, clean_text(), name="clean.conf")
    first = file_inventory(tmp_path, dirty, name="first.json")
    second = file_inventory(tmp_path, clean, name="second.json")
    code, out, _ = gather(capsys, first, as_json=True, store=database)
    assert code == 0
    assert json.loads(out)["summary"]["total"] > 0
    code, out, _ = gather(capsys, second, as_json=True, store=database)
    assert code == 0
    report = json.loads(out)
    assert report["findings"] == []
    assert sorted(item["rule_id"] for item in report["gone"]) == [WAN_RULE, UTM_RULE]
    for item in report["gone"]:
        assert sorted(item) == sorted(cli.GONE_KEYS)


def test_the_ssh_channel_is_called_with_what_the_inventory_holds(tmp_path, capsys, monkeypatch):
    text = clean_text()
    inventory_path = write_inventory(tmp_path, [ssh_item()])
    vault_path = write_ssh_vault(tmp_path)
    database = tmp_path / "audit.sqlite"
    seen = {}

    def fake(device, platform, address, port, credential, host_key_fingerprint, **rest):
        seen.update(
            device=device,
            platform=platform,
            address=address,
            port=port,
            login=credential.login,
            kind=credential.kind,
            key=credential.use(),
            host_key=host_key_fingerprint,
            legacy_ssh=rest.get("legacy_ssh", "not passed"),
        )
        source = "%s@%s" % (credential.login, address)
        snapshot = snapshot_of(text, "ssh", source, credential.login)
        first = step_event("ssh", "%s get system console" % source)
        taken = event_of(snapshot, "%s show" % source)
        return snapshot, (first, taken)

    monkeypatch.setattr(cli.collect, "collect_ssh", fake)
    code, out, err = gather(
        capsys,
        inventory_path,
        as_json=True,
        store=database,
        vault_path=vault_path,
    )
    assert code == 0
    assert err == ""
    assert seen == {
        "device": DEVICE,
        "platform": "fortios",
        "address": SSH_HOST,
        "port": SSH_PORT,
        "login": LOGIN,
        "kind": "ssh-key",
        "key": CANARY_KEY,
        "host_key": HOST_KEY,
        "legacy_ssh": None,
    }
    report = json.loads(out)
    assert report["collection"]["channel"] == "ssh"
    assert report["collection"]["source"] == "%s@%s" % (LOGIN, SSH_HOST)
    assert report["collection"]["profile"] == LOGIN
    assert report["collection"]["credential-kind"] == "ssh-key"
    assert report["collection"]["legacy_ssh"] == cli.LEGACY_NONE
    _, text_out, _ = gather(capsys, inventory_path, vault_path=vault_path)
    assert "collection-profile: %s" % LOGIN in text_out
    assert "collection-credential-kind: ssh-key" in text_out
    with Store(database) as store:
        recorded = store.last_run(TENANT, DEVICE)
        events = store.channel_events_for_run(TENANT, recorded["id"])
    assert len(events) == 2
    assert [item["outcome"] for item in events] == ["ok", "ok"]
    assert CANARY_KEY not in database_text(database)


def test_the_ssh_channel_takes_a_password_credential(tmp_path, capsys, monkeypatch):
    text = clean_text()
    inventory_path = write_inventory(tmp_path, [ssh_item()])
    vault_path = write_ssh_vault(tmp_path, value="replace-me", kind="password")
    seen = {}

    def fake(device, platform, address, port, credential, host_key_fingerprint, **rest):
        seen.update(kind=credential.kind, login=credential.login)
        source = "%s@%s" % (credential.login, address)
        snapshot = snapshot_of(text, "ssh", source, credential.login)
        return snapshot, (event_of(snapshot, "%s show" % source),)

    monkeypatch.setattr(cli.collect, "collect_ssh", fake)
    code, out, err = gather(capsys, inventory_path, as_json=True, vault_path=vault_path)
    assert code == 0
    assert err == ""
    assert seen == {"kind": "password", "login": LOGIN}
    assert json.loads(out)["collection"]["credential-kind"] == "password"


def test_the_ssh_channel_carries_the_legacy_profile_of_that_one_device(tmp_path, capsys, monkeypatch):
    text = clean_text()
    inventory_path = write_inventory(tmp_path, [ssh_item(legacy_ssh="rsa-sha1")])
    vault_path = write_ssh_vault(tmp_path)
    seen = {}

    def fake(device, platform, address, port, credential, host_key_fingerprint, **rest):
        seen.update(legacy_ssh=rest.get("legacy_ssh", "not passed"))
        source = "%s@%s" % (credential.login, address)
        snapshot = snapshot_of(text, "ssh", source, credential.login)
        return snapshot, (event_of(snapshot, "%s show" % source),)

    monkeypatch.setattr(cli.collect, "collect_ssh", fake)
    code, out, err = gather(capsys, inventory_path, as_json=True, vault_path=vault_path)
    assert code == 0
    assert err == ""
    assert seen == {"legacy_ssh": "rsa-sha1"}
    report = json.loads(out)
    assert report["collection"]["legacy_ssh"] == "rsa-sha1"
    text_code, text_out, _ = gather(capsys, inventory_path, vault_path=vault_path)
    assert text_code == 0
    assert "collection-legacy_ssh: rsa-sha1" in text_out


@pytest.mark.parametrize("profile", ("ssh-rsa", "HostKeyAlgorithms=+ssh-rsa", "RSA-SHA1", ""))
def test_collect_refuses_a_legacy_profile_the_inventory_does_not_know(
    tmp_path, capsys, monkeypatch, profile
):
    inventory_path = write_inventory(tmp_path, [ssh_item(legacy_ssh=profile)])
    vault_path = write_ssh_vault(tmp_path)
    called = []

    def fake(*args, **kwargs):
        called.append(kwargs)
        raise AssertionError("the collection must not start")

    monkeypatch.setattr(cli.collect, "collect_ssh", fake)
    code, out, err = gather(capsys, inventory_path, as_json=True, vault_path=vault_path)
    assert code == 2
    assert out == ""
    assert "legacy_ssh must be null for a device that speaks current algorithms" in err
    assert called == []


def test_a_legacy_profile_without_a_pinned_host_key_stops_the_collection(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    inventory_path = write_inventory(tmp_path, [device_item(source=path, legacy_ssh="rsa-sha1")])
    code, out, err = gather(capsys, inventory_path, as_json=True)
    assert code == 2
    assert out == ""
    assert "requires host_key_fingerprint" in err


def test_the_rest_channel_is_called_with_the_pinned_fingerprint(tmp_path, capsys, monkeypatch):
    text = clean_text()
    inventory_path = write_inventory(tmp_path, [rest_item()])
    vault_path = write_vault(tmp_path)
    seen = {}

    def fake(device, host, credential, profile, tls_fingerprint=None, **rest):
        seen.update(
            device=device,
            host=host,
            profile=profile,
            kind=credential.kind,
            pin=tls_fingerprint,
            token=credential.use(),
        )
        snapshot = snapshot_of(text, "fortios-rest", host, profile)
        return snapshot, event_of(snapshot, "POST %s/api/v2/monitor" % host)

    monkeypatch.setattr(cli.collect, "collect_fortios_rest", fake)
    code, out, err = gather(capsys, inventory_path, as_json=True, vault_path=vault_path)
    assert code == 0
    assert err == ""
    assert seen == {
        "device": DEVICE,
        "host": "https://%s" % REST_HOST,
        "profile": cli.DEFAULT_PROFILE,
        "kind": "api-token",
        "pin": TLS_FINGERPRINT,
        "token": CANARY_TOKEN,
    }
    report = json.loads(out)
    assert report["collection"]["channel"] == "fortios-rest"
    assert report["collection"]["source"] == "https://%s" % REST_HOST
    assert report["collection"]["credential-kind"] == "api-token"


def test_collect_takes_no_profile_option(tmp_path):
    path = write_config(tmp_path, clean_text())
    inventory_path = file_inventory(tmp_path, path)
    with pytest.raises(SystemExit) as failure:
        cli.main(
            [
                "collect",
                "--inventory",
                str(inventory_path),
                "--device",
                DEVICE,
                "--tenant",
                TENANT,
                "--profile",
                LOGIN,
            ]
        )
    assert failure.value.code == 2


def test_a_device_without_an_auditor_section_is_an_error(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    entry = device_item(source=path, auditor=None)
    entry["helper"] = {"account_role": "read-only"}
    inventory_path = write_inventory(tmp_path, [entry])
    code, out, err = gather(capsys, inventory_path)
    assert code == 2
    assert out == ""
    assert "carries no auditor section" in err


def test_an_unknown_device_is_an_error(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    inventory_path = file_inventory(tmp_path, path)
    code, out, err = gather(capsys, inventory_path, device="fw-absent")
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_a_broken_inventory_is_an_error(tmp_path, capsys):
    path = tmp_path / "inventory.json"
    path.write_text("{", encoding="utf-8")
    code, out, err = gather(capsys, path)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_collect_needs_an_inventory_a_device_and_a_tenant(tmp_path):
    for argv in (
        ["collect", "--device", DEVICE, "--tenant", TENANT],
        ["collect", "--inventory", "x.json", "--tenant", TENANT],
        ["collect", "--inventory", "x.json", "--device", DEVICE],
    ):
        with pytest.raises(SystemExit) as failure:
            cli.main(argv)
        assert failure.value.code == 2


def test_findings_do_not_change_the_collect_exit_code(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    inventory_path = file_inventory(tmp_path, path)
    code, out, err = gather(capsys, inventory_path, as_json=True)
    assert code == 0
    assert err == ""
    assert json.loads(out)["summary"]["total"] > 0


def test_a_store_that_cannot_be_opened_is_an_error(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    inventory_path = file_inventory(tmp_path, path)
    code, out, err = gather(capsys, inventory_path, store=tmp_path / "nowhere" / "audit.sqlite")
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_collect_baseline_accept_records_who_and_why(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    inventory_path = file_inventory(tmp_path, path)
    database = tmp_path / "audit.sqlite"
    code, out, err = gather(
        capsys,
        inventory_path,
        as_json=True,
        store=database,
        accept=("radek", "ticket NET-2"),
    )
    assert code == 0
    assert "baseline: accepted" in err
    assert json.loads(out)["summary"]["total"] > 0
    with Store(database) as store:
        entries = store.baseline_entries(TENANT, DEVICE)
    assert entries
    assert {item["accepted_by"] for item in entries} == {"radek"}
    assert {item["note"] for item in entries} == {"ticket NET-2"}


def test_collect_baseline_accept_without_store_is_an_error(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    inventory_path = file_inventory(tmp_path, path)
    code, out, err = gather(capsys, inventory_path, accept=("radek", "ticket NET-2"))
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_a_suppression_reaches_the_collected_findings(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    inventory_path = file_inventory(tmp_path, path)
    waivers = write_suppressions(tmp_path, [suppression(WAN_RULE, WAN_OBJECT, FUTURE)])
    code, out, err = gather(capsys, inventory_path, as_json=True, suppressions=waivers)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert states_by_rule(report)[WAN_RULE] == "suppressed"
    assert states_by_rule(report)[UTM_RULE] == "new"


def test_collect_output_is_byte_identical_for_the_same_input(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    inventory_path = file_inventory(tmp_path, path)
    for as_json in (False, True):
        _, one, err_one = gather(capsys, inventory_path, as_json=as_json)
        _, two, err_two = gather(capsys, inventory_path, as_json=as_json)
        assert one.encode("utf-8") == two.encode("utf-8")
        assert err_one == err_two == ""


EXOS_DEVICE = "sw-example"
EXOS_SECTIONS = ("vlan", "ems", "telnetd")
EXOS_TELNET_RULE = "exos.mgmt.telnet-enabled"
EXOS_SYSLOG_RULE = "exos.logging.no-syslog-target"


def exos_clean_text():
    return (FIXTURES / "exos_clean.conf").read_text(encoding="utf-8")


def exos_positive_text(rule_id):
    return (FIXTURES / "rules" / rule_id / "positive.conf").read_text(encoding="utf-8")


def exos_inventory(directory, config, sections=EXOS_SECTIONS, name="exos-inventory.json"):
    return write_inventory(
        directory,
        [
            device_item(
                source=config, sections=sections, platform="exos", name=EXOS_DEVICE
            )
        ],
        name=name,
    )


def test_both_platforms_are_offered_on_the_command_line():
    assert sorted(cli.PLATFORMS) == ["exos", "fortios"]


def test_an_exos_configuration_is_audited_by_the_exos_catalog(tmp_path, capsys):
    path = write_config(tmp_path, exos_clean_text(), name="switch.conf")
    code, out, err = audit(capsys, path, as_json=True, platform="exos", device=EXOS_DEVICE)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["platform"] == "exos"
    assert report["findings"] == []
    assert report["rules_version"].startswith("exos:9:")


def test_an_exos_defect_is_reported_over_the_command_line(tmp_path, capsys):
    path = write_config(tmp_path, exos_positive_text(EXOS_TELNET_RULE), name="switch.conf")
    code, out, err = audit(capsys, path, as_json=True, platform="exos", device=EXOS_DEVICE)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert [item["rule_id"] for item in report["findings"]] == [EXOS_TELNET_RULE]


def test_an_exos_configuration_is_not_parsed_by_the_fortios_parser(tmp_path, capsys):
    path = write_config(tmp_path, exos_clean_text(), name="switch.conf")
    code, out, _ = audit(capsys, path, as_json=True, device=EXOS_DEVICE)
    assert code == 0
    assert json.loads(out)["findings"] != []


def test_collect_no_longer_refuses_an_exos_device(tmp_path, capsys):
    path = write_config(tmp_path, exos_clean_text(), name="switch.conf")
    inventory_path = exos_inventory(tmp_path, path)
    code, out, err = gather(capsys, inventory_path, device=EXOS_DEVICE, as_json=True)
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["platform"] == "exos"
    assert report["findings"] == []
    assert report["collection"]["channel"] == "file"


def test_collect_reports_an_exos_finding_over_a_complete_view(tmp_path, capsys):
    path = write_config(tmp_path, exos_positive_text(EXOS_SYSLOG_RULE), name="switch.conf")
    inventory_path = exos_inventory(tmp_path, path)
    code, out, err = gather(capsys, inventory_path, device=EXOS_DEVICE, as_json=True)
    assert code == 0
    assert err == ""
    assert [item["rule_id"] for item in json.loads(out)["findings"]] == [EXOS_SYSLOG_RULE]


def test_an_incomplete_exos_view_still_stops_the_catalog(tmp_path, capsys):
    path = write_config(tmp_path, exos_positive_text(EXOS_SYSLOG_RULE), name="switch.conf")
    inventory_path = exos_inventory(
        tmp_path, path, sections=EXOS_SECTIONS + ("poe",), name="narrow-exos.json"
    )
    code, out, err = gather(capsys, inventory_path, device=EXOS_DEVICE, as_json=True)
    assert code == 0
    assert err == ""
    findings = json.loads(out)["findings"]
    assert [item["rule_id"] for item in findings] == ["exos.snapshot.incomplete"]


def test_collect_still_refuses_a_platform_without_a_catalogue(tmp_path, capsys):
    path = write_config(tmp_path, exos_clean_text(), name="host.conf")
    inventory_path = write_inventory(
        tmp_path,
        [device_item(source=path, sections=("vlan",), platform="linux", name="host-a")],
        name="linux-inventory.json",
    )
    code, out, err = gather(capsys, inventory_path, device="host-a", as_json=True)
    assert code == 2
    assert out == ""
    assert "the auditor holds no rule catalog for it" in err
    assert "linux" in err


def test_migrate_suppressions_writes_a_bound_file_and_leaves_the_input_alone(tmp_path, capsys):
    source = write_v1_suppressions(tmp_path, [v1_suppression(WAN_RULE, WAN_OBJECT, FUTURE)])
    before = source.read_bytes()
    target = tmp_path / "waivers-v2.json"
    code, out, err = invoke(
        capsys,
        [
            "migrate-suppressions",
            "--input",
            str(source),
            "--output",
            str(target),
            "--tenant",
            TENANT,
        ],
    )
    assert code == 0
    assert err == ""
    assert out == "migrated 1 suppressions of tenant %s into %s\n" % (TENANT, target)
    assert source.read_bytes() == before
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["version"] == SUPPRESSION_FILE_VERSION
    assert document["tenant"] == TENANT
    assert document["suppressions"][0]["fingerprint"] == fingerprint_of(
        WAN_RULE, rule_version(WAN_RULE), TENANT, DEVICE, WAN_OBJECT
    )


def test_migrate_suppressions_prints_nothing_of_the_document_it_reads(tmp_path, capsys):
    item = v1_suppression(WAN_RULE, WAN_OBJECT, FUTURE, reason=CANARY)
    item["created"] = "not a moment"
    source = write_v1_suppressions(tmp_path, [item])
    code, out, err = invoke(
        capsys,
        [
            "migrate-suppressions",
            "--input",
            str(source),
            "--output",
            str(tmp_path / "waivers-v2.json"),
            "--tenant",
            TENANT,
        ],
    )
    assert code == 2
    assert out == ""
    assert CANARY not in err
    assert not (tmp_path / "waivers-v2.json").exists()


def test_the_migrated_file_silences_the_finding_it_was_written_for(tmp_path, capsys):
    source = write_v1_suppressions(tmp_path, [v1_suppression(WAN_RULE, WAN_OBJECT, FUTURE)])
    target = tmp_path / "waivers-v2.json"
    invoke(
        capsys,
        ["migrate-suppressions", "--input", str(source), "--output", str(target), "--tenant", TENANT],
    )
    path = write_config(tmp_path, dirty_text())
    code, out, err = invoke(capsys, full_args(path, as_json=True, suppressions=target))
    assert code == 0
    assert err == ""
    assert states_by_rule(json.loads(out))[WAN_RULE] == "suppressed"


def old_store(tmp_path, capsys, name="audit.sqlite"):
    path = write_config(tmp_path, dirty_text())
    database = tmp_path / name
    code, _, _ = invoke(capsys, full_args(path, store=database))
    assert code == 0
    connection = sqlite3.connect(str(database), isolation_level=None)
    connection.execute("PRAGMA user_version = 0")
    connection.close()
    return path, database


def test_an_unmigrated_store_stops_the_run_and_names_the_migration(tmp_path, capsys):
    path, database = old_store(tmp_path, capsys)
    code, out, err = invoke(capsys, full_args(path, store=database))
    assert code == 2
    assert out == ""
    assert "schema version 1" in err
    assert "migrate-store" in err


def test_migrate_store_lets_the_cli_open_the_store_again(tmp_path, capsys):
    path, database = old_store(tmp_path, capsys)
    code, out, err = invoke(capsys, ["migrate-store", "--store", str(database)])
    assert code == 0
    assert err == ""
    assert out.startswith("migrated ")
    assert "baseline entries" in out
    code, out, err = invoke(capsys, full_args(path, as_json=True, store=database))
    assert code == 0
    assert json.loads(out)["states"]["gone"] == 0


def test_migrate_store_needs_a_store_that_exists(tmp_path, capsys):
    code, out, err = invoke(capsys, ["migrate-store", "--store", str(tmp_path / "nowhere.sqlite")])
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")


def test_the_cli_and_the_read_only_surface_refuse_the_same_file_alike(tmp_path):
    waivers = write_suppressions(
        tmp_path,
        [suppression(WAN_RULE, WAN_OBJECT, FUTURE, tenant="tenant-b")],
        tenant="tenant-b",
    )
    with pytest.raises(SuppressionError) as shared:
        load_for_tenant(waivers, TENANT)
    with pytest.raises(cli.Failure) as through_cli:
        cli._load_suppressions(waivers, TENANT)
    assert str(shared.value) in str(through_cli.value)


def test_reciprocal_incomplete_history_preserves_last_evaluated(tmp_path, capsys):
    from datetime import datetime, timezone
    from netops_auditor import query
    from netops_auditor.store import StoreError
    path = write_config(tmp_path, dirty_text())
    database = tmp_path / "history.sqlite"
    complete = file_inventory(tmp_path, path)
    first = json.loads(gather(capsys, complete, store=database, as_json=True)[1])
    originals = {item["fingerprint"] for item in first["findings"]}
    with Store(database) as store:
        first_id = store.last_run(TENANT, DEVICE)["id"]
        assert store.accept_baseline(TENANT, DEVICE, first_id, "reviewer", "fixture") == 2
    narrow = file_inventory(tmp_path, path, sections=SECTIONS + (MISSING_SECTION,), name="narrow.json")
    for _ in range(2):
        code, out, err = gather(capsys, narrow, store=database, as_json=True)
        assert code == 0
        partial = json.loads(out)
        assert partial["gone"] == []
        assert partial["evaluation"] == "not-evaluated"
        assert {item["fingerprint"] for item in partial["not_evaluated"]} == originals
        assert cli.main(status_args(database, as_json=True)) == 1
        assert json.loads(capsys.readouterr().out)["state"] == "incomplete"
        with Store(database) as store:
            current_id = store.last_run(TENANT, DEVICE)["id"]
            listing = query.list_findings(store, TENANT, DEVICE, now=datetime.now(timezone.utc))
            assert {item["fingerprint"] for item in listing["findings"] if item["state"] == "not-evaluated"} == originals
            assert listing["gone"] == ()
            status = query.audit_status(store, TENANT, DEVICE, now=datetime.now(timezone.utc))
            assert status["devices"][0]["state"] == "incomplete"
            for fingerprint in originals:
                assert query.finding_detail(store, TENANT, DEVICE, fingerprint, now=datetime.now(timezone.utc))["state"] == "not-evaluated"
            with pytest.raises(query.QueryError):
                query.compare(store, TENANT, DEVICE, first_id, current_id)
            with pytest.raises(StoreError):
                store.accept_baseline(TENANT, DEVICE, current_id, "reviewer", "fixture")
            assert set(store.baseline_fingerprints(TENANT, DEVICE)) == originals
            assert query.compare(store, TENANT, DEVICE, first_id, first_id)["counts"]["kept"] == 2
    again = json.loads(gather(capsys, complete, store=database, as_json=True)[1])
    assert again["gone"] == []
    assert again["states"]["open-known"] == 2
    path.write_text(clean_text())
    cleaned = json.loads(gather(capsys, complete, store=database, as_json=True)[1])
    assert {item["fingerprint"] for item in cleaned["gone"]} == originals


def sarif_args(path, device=DEVICE, platform="fortios", suppressions=None):
    argv = run_args(path, device=device, platform=platform) + ["--sarif"]
    if suppressions is not None:
        argv.extend(["--suppressions", str(suppressions)])
    return argv


def sarif_run(capsys, argv):
    code, out, err = invoke(capsys, argv)
    assert code == 0, err
    assert err == ""
    return json.loads(out)


def test_sarif_carries_every_finding_of_the_json_report(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    write_config(tmp_path, dirty_text())
    _, out, _ = audit(capsys, Path("device.conf"), as_json=True)
    report = json.loads(out)
    document = sarif_run(capsys, sarif_args(Path("device.conf")))
    assert document["version"] == "2.1.0"
    assert len(document["runs"]) == 1
    run = document["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "netops-auditor"
    assert driver["version"] == sarif.__version__
    assert [rule["id"] for rule in driver["rules"]] == [rule.id for rule in cli._load_rules("fortios")]
    expected = {(item["rule_id"], item["fingerprint"], item["line"], item["severity"]) for item in report["findings"]}
    produced = set()
    for result in run["results"]:
        assert driver["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "device.conf"
        severity = {v: k for k, v in sarif.LEVELS.items() if k != "info"}[result["level"]]
        produced.add((result["ruleId"], result["partialFingerprints"][sarif.FINGERPRINT_KEY], location["region"]["startLine"], severity))
        assert "suppressions" not in result
    assert produced == expected
    assert run["properties"]["devices"][0]["snapshot_sha256"] == report["snapshot_sha256"]
    assert CANARY not in json.dumps(document)


def test_sarif_of_a_clean_configuration_has_no_result(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    document = sarif_run(capsys, sarif_args(path))
    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"]


def test_sarif_marks_a_suppressed_finding(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    waivers = write_suppressions(tmp_path, [suppression(WAN_RULE, WAN_OBJECT, FUTURE)])
    run = sarif_run(capsys, sarif_args(path, suppressions=waivers))["runs"][0]
    marked = {result["ruleId"]: result.get("suppressions") for result in run["results"]}
    assert marked[WAN_RULE] == [{"kind": "external", "status": "accepted"}]
    assert marked[UTM_RULE] is None


def test_sarif_severity_mapping_follows_the_catalog(tmp_path, capsys):
    path = write_config(tmp_path, dirty_text())
    run = sarif_run(capsys, sarif_args(path))["runs"][0]
    for rule, catalog in zip(run["tool"]["driver"]["rules"], cli._load_rules("fortios")):
        assert rule["defaultConfiguration"]["level"] == sarif.LEVELS[catalog.severity]
        assert rule["properties"].get("security-severity") == sarif.SECURITY_SEVERITY.get(catalog.severity)
        assert "security" in rule["properties"]["tags"]


def test_sarif_and_json_exclude_each_other(tmp_path, capsys):
    path = write_config(tmp_path, clean_text())
    code, out, err = invoke(capsys, sarif_args(path) + ["--json"])
    assert code == cli.EXIT_ERROR
    assert out == ""
    assert "exclude each other" in err


def test_sarif_uri_of_an_absolute_path_is_a_file_uri(tmp_path):
    assert sarif.artifact_uri(str(tmp_path / "a b.conf")) == (tmp_path / "a b.conf").as_uri()
    assert sarif.artifact_uri("./backups/a b.conf") == "backups/a%20b.conf"


def write_sarif(tmp_path, capsys, name, text, device, platform="fortios"):
    config = write_config(tmp_path, text, name=name + ".conf")
    code, out, err = invoke(capsys, sarif_args(config, device=device, platform=platform))
    assert code == 0, err
    target = tmp_path / (name + ".sarif")
    target.write_text(out, encoding="utf-8")
    return target


def test_merge_sarif_keeps_every_result_under_one_run(tmp_path, capsys):
    first = write_sarif(tmp_path, capsys, "fw-a", dirty_text(), "fw-a")
    second = write_sarif(tmp_path, capsys, "fw-b", dirty_text(), "fw-b")
    exos = write_sarif(tmp_path, capsys, "sw-a", (FIXTURES / "exos_clean.conf").read_text(encoding="utf-8"), "sw-a", "exos")
    parts = [json.loads(path.read_text(encoding="utf-8"))["runs"][0] for path in (first, second, exos)]
    output = tmp_path / "all.sarif"
    code, out, err = invoke(capsys, ["merge-sarif", "--output", str(output), str(first), str(second), str(exos)])
    assert code == 0, err
    run = json.loads(output.read_text(encoding="utf-8"))["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len({rule["id"] for rule in rules}) == len(rules)
    assert len(run["results"]) == sum(len(part["results"]) for part in parts)
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
    assert [device["device"] for device in run["properties"]["devices"]] == ["fw-a", "fw-b", "sw-a"]
    assert "merged %d results from 3 files" % len(run["results"]) in out


def test_merge_sarif_refuses_foreign_or_inconsistent_input(tmp_path, capsys):
    own = write_sarif(tmp_path, capsys, "fw-a", dirty_text(), "fw-a")
    document = json.loads(own.read_text(encoding="utf-8"))
    cases = {}
    foreign = json.loads(json.dumps(document))
    foreign["runs"][0]["tool"]["driver"]["name"] = "other-tool"
    cases["foreign"] = (foreign, "was not produced by")
    older = json.loads(json.dumps(document))
    older["runs"][0]["tool"]["driver"]["version"] = "0.0.1"
    cases["older"] = (older, "not %s" % sarif.__version__)
    changed = json.loads(json.dumps(document))
    changed["runs"][0]["tool"]["driver"]["rules"][0]["help"]["text"] = "changed"
    cases["changed"] = (changed, "differently")
    undescribed = json.loads(json.dumps(document))
    undescribed["runs"][0]["results"][0]["ruleId"] = "fortios.unknown"
    cases["undescribed"] = (undescribed, "does not describe")
    twice = json.loads(json.dumps(document))
    twice["runs"].append(twice["runs"][0])
    cases["twice"] = (twice, "exactly one run")
    for name, (item, message) in cases.items():
        path = tmp_path / (name + ".sarif")
        path.write_text(json.dumps(item), encoding="utf-8")
        output = tmp_path / (name + "-out.sarif")
        arguments = [str(own), str(path)] if name == "changed" else [str(path)]
        code, out, err = invoke(capsys, ["merge-sarif", "--output", str(output)] + arguments)
        assert code == cli.EXIT_ERROR, name
        assert message in err, (name, err)
        assert not output.exists(), name
