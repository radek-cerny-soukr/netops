import ast
import asyncio
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastmcp")

from netops_auditor import mcp_server, query
from netops_auditor.engine import load_catalog
from netops_auditor.findings import Finding
from netops_auditor.state import STATE_GONE, STATE_NEW, STATE_OPEN_KNOWN, STATE_SUPPRESSED
from netops_auditor.store import MOMENT_FORMAT, Store
from netops_auditor.suppressions import fingerprint_of

TENANT = "tenant-a"
DEVICE = "fw-a.example.invalid"
OTHER_DEVICE = "fw-b.example.invalid"
PLATFORM = "fortios"
RULES_VERSION = "fortios:1:catalog"

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = COMPONENT_ROOT / "src" / "netops_auditor"

DEVICE_REACHING_MODULES = ("collect", "inventory", "cli")
CORE_DEVICE_REACHING_MODULES = ("vault", "ssh", "session", "sftp", "hostkey")

BANNED_TOOL_NAMES = (
    "suppress",
    "suppress_finding",
    "collect",
    "run",
    "run_audit",
    "apply",
    "accept_baseline",
    "forget_baseline",
    "record_run",
    "get_config",
)

IMPORT_PROBE = """
import json
import sys

sys.path.insert(0, sys.argv[1])
import netops_auditor.mcp_server

print(json.dumps(sorted(name for name in sys.modules if name.startswith("netops_auditor"))))
"""


def _finding(rule_id, object_key, severity="high", device=DEVICE, rule_version=1):
    return Finding(
        rule_id=rule_id,
        rule_version=rule_version,
        device=device,
        object_key=object_key,
        severity=severity,
        rule_class="fakt",
        section="firewall policy",
        line=12,
        evidence=(("attribute", "srcaddr"), ("value", "198.51.100.0/24")),
    )


def _moment(now, hours):
    return (now - timedelta(hours=hours)).strftime(MOMENT_FORMAT)


@pytest.fixture(autouse=True)
def clean_configuration():
    mcp_server._CONFIGURATION = None
    yield
    mcp_server._CONFIGURATION = None


@pytest.fixture
def audited(tmp_path):
    now = datetime.now(timezone.utc)
    path = tmp_path / "audit.db"
    first = (
        _finding("L1-001", "firewall policy/1"),
        _finding("L1-002", "system interface/wan1", severity="medium"),
    )
    second = (
        _finding("L1-001", "firewall policy/1"),
        _finding("L1-003", "system dns", severity="low"),
    )
    with Store(path) as store:
        first_run = store.record_run(
            TENANT, DEVICE, "sha-first", "history/first.conf", RULES_VERSION, first,
            started_at=_moment(now, 50),
        )
        store.accept_baseline(TENANT, DEVICE, first_run, "radek", "accepted at the first review")
        second_run = store.record_run(
            TENANT, DEVICE, "sha-second", "history/second.conf", RULES_VERSION, second,
            started_at=_moment(now, 2),
        )
        other_run = store.record_run(
            TENANT, OTHER_DEVICE, "sha-other", "history/other.conf", RULES_VERSION,
            (_finding("L1-001", "firewall policy/9", device=OTHER_DEVICE),),
            started_at=_moment(now, 3),
        )
    return SimpleNamespace(
        path=path,
        first_run=first_run,
        second_run=second_run,
        other_run=other_run,
        suppressed_fingerprint=fingerprint_of("L1-003", 1, DEVICE, "system dns"),
    )


def _environment(audited, suppressions_path=None):
    values = {
        mcp_server.STORE_VARIABLE: str(audited.path),
        mcp_server.TENANT_VARIABLE: TENANT,
        mcp_server.CATALOG_VARIABLE: PLATFORM,
    }
    if suppressions_path is not None:
        values[mcp_server.SUPPRESSIONS_VARIABLE] = str(suppressions_path)
    return values


@pytest.fixture
def configured(audited):
    mcp_server.configure(_environment(audited))
    return audited


@pytest.fixture
def suppressed(audited, tmp_path):
    path = tmp_path / "suppressions.json"
    document = {
        "version": 1,
        "suppressions": [
            {
                "fingerprint": audited.suppressed_fingerprint,
                "rule_id": "L1-003",
                "rule_version": 1,
                "device": DEVICE,
                "object_key": "system dns",
                "reason": "resolver moves during the next maintenance window",
                "author": "radek",
                "created": "2026-09-01T08:00:00Z",
                "expires": "2099-01-01T00:00:00Z",
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    mcp_server.configure(_environment(audited, path))
    return SimpleNamespace(audited=audited, path=path)


def _package_imports(module_name):
    tree = ast.parse((PACKAGE_ROOT / ("%s.py" % module_name)).read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level and node.module is None:
                found.update(alias.name for alias in node.names)
            elif node.level and node.module:
                found.add(node.module.split(".")[0])
            elif node.module and node.module.split(".")[0] == "netops_auditor":
                parts = node.module.split(".")
                if len(parts) > 1:
                    found.add(parts[1])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == "netops_auditor" and len(parts) > 1:
                    found.add(parts[1])
    return frozenset(name for name in found if (PACKAGE_ROOT / ("%s.py" % name)).is_file())


def _core_imports(module_name):
    tree = ast.parse((PACKAGE_ROOT / ("%s.py" % module_name)).read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and not node.level and node.module:
            parts = node.module.split(".")
            if parts[0] == "netops_core":
                found.update(parts[1:2] or [alias.name for alias in node.names])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == "netops_core" and len(parts) > 1:
                    found.add(parts[1])
    return frozenset(found)


def _import_closure(module_name):
    seen, pending = set(), [module_name]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(_package_imports(current))
    return frozenset(seen)


def test_the_surface_holds_exactly_six_tools_with_the_agreed_names():
    tools = asyncio.run(mcp_server.mcp.list_tools())
    names = sorted(tool.name for tool in tools)
    assert len(mcp_server.TOOL_NAMES) == 6
    assert names == sorted(mcp_server.TOOL_NAMES)
    assert names == sorted(
        ("audit_status", "list_rules", "rule_detail", "list_findings", "finding_detail", "compare")
    )
    for banned in BANNED_TOOL_NAMES:
        assert banned not in names


def test_every_tool_carries_a_description():
    tools = asyncio.run(mcp_server.mcp.list_tools())
    for tool in tools:
        assert tool.description and tool.description.strip()


def test_the_module_imports_no_device_reaching_module_statically():
    closure = _import_closure("mcp_server")
    assert {"query", "store", "engine", "suppressions", "checks_fortios"} <= closure
    for name in DEVICE_REACHING_MODULES:
        assert name not in closure
        assert (PACKAGE_ROOT / ("%s.py" % name)).is_file()
    reached = frozenset().union(*(_core_imports(name) for name in closure))
    for name in CORE_DEVICE_REACHING_MODULES:
        assert name not in reached
    assert _core_imports("collect") & {"ssh", "hostkey"}


def test_importing_the_server_loads_no_device_reaching_module():
    result = subprocess.run(
        [sys.executable, "-c", IMPORT_PROBE, str(COMPONENT_ROOT / "src")],
        capture_output=True,
        text=True,
        check=True,
    )
    loaded = json.loads(result.stdout)
    assert "netops_auditor.mcp_server" in loaded
    assert "netops_auditor.query" in loaded
    assert "netops_auditor.store" in loaded
    for name in DEVICE_REACHING_MODULES:
        assert ("netops_auditor.%s" % name) not in loaded
    for name in CORE_DEVICE_REACHING_MODULES:
        assert ("netops_core.%s" % name) not in loaded


def test_the_server_opens_the_store_read_only(configured, monkeypatch):
    seen = {}
    real_connect = sqlite3.connect

    def spy(target, *args, **keywords):
        seen["target"] = target
        seen["uri"] = keywords.get("uri")
        return real_connect(target, *args, **keywords)

    monkeypatch.setattr(mcp_server.sqlite3, "connect", spy)
    mcp_server.open_store().close()
    assert seen["uri"] is True
    assert seen["target"].startswith("file:")
    assert seen["target"].endswith("?mode=ro")


def test_a_write_over_the_server_connection_raises(configured):
    with mcp_server.open_store() as store:
        assert store._connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 3
        with pytest.raises(sqlite3.OperationalError):
            store._connection.execute(
                "INSERT INTO runs (tenant, device, started_at, snapshot_sha256, snapshot_source,"
                " rules_version) VALUES (?, ?, ?, ?, ?, ?)",
                (TENANT, DEVICE, "2026-09-12T10:00:00Z", "x", "y", "z"),
            )
        with pytest.raises(sqlite3.OperationalError):
            store._connection.execute("DELETE FROM findings")
        with pytest.raises(sqlite3.OperationalError):
            store._connection.execute("UPDATE findings SET severity = 'info'")
        with pytest.raises(sqlite3.OperationalError):
            store._connection.execute("CREATE TABLE smuggled (id INTEGER PRIMARY KEY)")
    with Store(configured.path) as store:
        assert len(store.runs_for_device(TENANT, DEVICE)) == 2
        assert len(store.findings_for_run(TENANT, configured.second_run)) == 2


def test_store_write_methods_fail_over_the_server_connection(configured):
    with mcp_server.open_store() as store:
        with pytest.raises(sqlite3.OperationalError):
            store.record_run(
                TENANT, DEVICE, "sha-smuggled", "history/smuggled.conf", RULES_VERSION,
                (_finding("L1-009", "firewall policy/3"),),
            )
        with pytest.raises(sqlite3.OperationalError):
            store.accept_baseline(TENANT, DEVICE, configured.second_run, "someone", "note")
        with pytest.raises(sqlite3.OperationalError):
            store.forget_baseline(TENANT, DEVICE, configured.suppressed_fingerprint)
    with Store(configured.path) as store:
        assert len(store.runs_for_device(TENANT, DEVICE)) == 2
        assert len(store.baseline_entries(TENANT, DEVICE)) == 2


def test_audit_status_reads_the_tenant_and_takes_its_parameters(configured):
    status = mcp_server.audit_status()
    assert status["tenant"] == TENANT
    assert tuple(item["device"] for item in status["devices"]) == (DEVICE, OTHER_DEVICE)
    assert status["stale_after_hours"] == query.DEFAULT_STALE_AFTER_HOURS
    assert status["totals"]["devices"] == 2
    one = mcp_server.audit_status(device=DEVICE)
    assert tuple(item["device"] for item in one["devices"]) == (DEVICE,)
    assert one["devices"][0]["run_id"] == configured.second_run
    assert one["devices"][0]["state"] == query.STATUS_FRESH
    assert one["devices"][0]["findings_total"] == 2
    stale = mcp_server.audit_status(device=DEVICE, stale_after_hours=1.0)
    assert stale["stale_after_hours"] == 1.0
    assert stale["devices"][0]["state"] == query.STATUS_STALE
    unknown = mcp_server.audit_status(device="fw-z.example.invalid")
    assert unknown["never_audited"] == ("fw-z.example.invalid",)


def test_audit_status_returns_what_query_returns(configured):
    with Store(configured.path) as store:
        expected = query.audit_status(
            store, TENANT, device=DEVICE, now=datetime.now(timezone.utc),
        )
    actual = mcp_server.audit_status(device=DEVICE)
    assert set(actual) == set(expected) == set(query.STATUS_KEYS)
    assert set(actual["devices"][0]) == set(query.DEVICE_STATUS_KEYS)
    for name in ("tenant", "stale_after_hours", "never_audited", "totals"):
        assert actual[name] == expected[name]
    for name in query.DEVICE_STATUS_KEYS:
        if name != "age_hours":
            assert actual["devices"][0][name] == expected["devices"][0][name]


def test_rule_tools_read_the_configured_catalog(configured):
    rules = load_catalog(PLATFORM)
    listed = mcp_server.list_rules()
    assert listed == query.list_rules(rules)
    assert len(listed) == len(rules)
    assert set(listed[0]) == set(query.RULE_KEYS)
    rule_id = listed[0]["id"]
    detail = mcp_server.rule_detail(rule_id)
    assert detail == query.rule_detail(rules, rule_id)
    assert set(detail) == set(query.RULE_DETAIL_KEYS)
    with pytest.raises(query.QueryError):
        mcp_server.rule_detail("no.such.rule")


def test_list_findings_returns_what_query_returns(configured):
    with Store(configured.path) as store:
        expected = query.list_findings(
            store, TENANT, DEVICE, suppressions=(), now=datetime.now(timezone.utc),
        )
    assert mcp_server.list_findings(DEVICE) == expected
    assert set(expected) == set(query.LISTING_KEYS)


def test_list_findings_passes_every_filter(configured):
    listing = mcp_server.list_findings(DEVICE)
    assert listing["run_id"] == configured.second_run
    assert listing["run_state"] == query.RUN_PRESENT
    assert listing["counts"][STATE_NEW] == 1
    assert listing["counts"][STATE_OPEN_KNOWN] == 1
    assert listing["counts"][STATE_GONE] == 1
    assert listing["groups"] == ()
    high = mcp_server.list_findings(DEVICE, severity="high")
    assert {item["severity"] for item in high["findings"]} == {"high"}
    assert high["total"] == 1
    new_only = mcp_server.list_findings(DEVICE, state=STATE_NEW)
    assert {item["state"] for item in new_only["findings"]} == {STATE_NEW}
    assert tuple(item["rule_id"] for item in new_only["findings"]) == ("L1-003",)
    gone_only = mcp_server.list_findings(DEVICE, state=STATE_GONE)
    assert tuple(item["rule_id"] for item in gone_only["gone"]) == ("L1-002",)
    grouped = mcp_server.list_findings(DEVICE, group_by="object")
    assert tuple(group["object_key"] for group in grouped["groups"])
    assert set(grouped["groups"][0]) == set(query.GROUP_KEYS)
    future = mcp_server.list_findings(DEVICE, since="2099-01-01T00:00:00Z")
    assert future["run_state"] == query.RUN_BEFORE_SINCE
    assert future["findings"] == ()
    other = mcp_server.list_findings(OTHER_DEVICE)
    assert other["device"] == OTHER_DEVICE
    assert other["run_id"] == configured.other_run
    with pytest.raises(query.QueryError):
        mcp_server.list_findings(DEVICE, severity="critical")


def test_list_findings_reads_the_configured_suppressions(suppressed):
    listing = mcp_server.list_findings(DEVICE)
    states = {item["rule_id"]: item["state"] for item in listing["findings"]}
    assert states["L1-003"] == STATE_SUPPRESSED
    assert states["L1-001"] == STATE_OPEN_KNOWN
    assert listing["counts"][STATE_SUPPRESSED] == 1
    assert listing["counts"][STATE_NEW] == 0


def test_finding_detail_passes_the_fingerprint_and_returns_what_query_returns(configured):
    listing = mcp_server.list_findings(DEVICE)
    entry = next(item for item in listing["findings"] if item["rule_id"] == "L1-001")
    with Store(configured.path) as store:
        expected = query.finding_detail(
            store, TENANT, DEVICE, entry["fingerprint"], suppressions=(),
            now=datetime.now(timezone.utc),
        )
    detail = mcp_server.finding_detail(DEVICE, entry["fingerprint"])
    assert detail == expected
    assert set(detail) == set(query.DETAIL_KEYS)
    assert detail["tenant"] == TENANT
    assert detail["device"] == DEVICE
    assert detail["run_id"] == configured.second_run
    assert detail["baseline"]["accepted_by"] == "radek"
    assert detail["suppression"] is None
    assert mcp_server.finding_detail(DEVICE, "0" * 64) is None


def test_finding_detail_reports_the_suppression(suppressed):
    detail = mcp_server.finding_detail(DEVICE, suppressed.audited.suppressed_fingerprint)
    assert detail["state"] == STATE_SUPPRESSED
    assert set(detail["suppression"]) == set(query.SUPPRESSION_KEYS)
    assert detail["suppression"]["author"] == "radek"
    assert detail["suppression"]["active"] is True


def test_compare_passes_both_runs_and_returns_what_query_returns(configured):
    with Store(configured.path) as store:
        expected = query.compare(store, TENANT, DEVICE, configured.first_run, configured.second_run)
    result = mcp_server.compare(DEVICE, configured.first_run, configured.second_run)
    assert result == expected
    assert set(result) == set(query.COMPARE_KEYS)
    assert result["counts"] == {"added": 1, "removed": 1, "kept": 1}
    assert tuple(item["rule_id"] for item in result["added"]) == ("L1-003",)
    assert tuple(item["rule_id"] for item in result["removed"]) == ("L1-002",)
    swapped = mcp_server.compare(DEVICE, configured.second_run, configured.first_run)
    assert tuple(item["rule_id"] for item in swapped["added"]) == ("L1-002",)
    assert tuple(item["rule_id"] for item in swapped["removed"]) == ("L1-003",)
    with pytest.raises(query.QueryError):
        mcp_server.compare(DEVICE, configured.first_run, configured.other_run)


def test_tools_answer_over_the_mcp_surface(configured):
    listed = asyncio.run(mcp_server.mcp.call_tool("list_rules", {}))
    assert len(listed.structured_content["result"]) == len(mcp_server.list_rules())
    findings = asyncio.run(mcp_server.mcp.call_tool("list_findings", {"device": DEVICE}))
    assert findings.structured_content["device"] == DEVICE
    assert findings.structured_content["run_id"] == configured.second_run
    status = asyncio.run(mcp_server.mcp.call_tool("audit_status", {"device": DEVICE}))
    assert status.structured_content["tenant"] == TENANT


def test_configure_names_every_missing_variable():
    with pytest.raises(mcp_server.ConfigurationError) as error:
        mcp_server.configure({})
    message = str(error.value)
    for name in mcp_server.REQUIRED_VARIABLES:
        assert name in message
    assert mcp_server._CONFIGURATION is None


def test_configure_names_the_one_missing_variable(audited):
    values = _environment(audited)
    del values[mcp_server.TENANT_VARIABLE]
    with pytest.raises(mcp_server.ConfigurationError) as error:
        mcp_server.configure(values)
    assert "missing: %s" % mcp_server.TENANT_VARIABLE in str(error.value)


def test_configure_rejects_a_store_that_is_not_a_file(tmp_path, audited):
    values = _environment(audited)
    values[mcp_server.STORE_VARIABLE] = str(tmp_path / "absent.db")
    with pytest.raises(mcp_server.ConfigurationError) as error:
        mcp_server.configure(values)
    assert "absent.db" in str(error.value)


def test_configure_rejects_an_unknown_platform(audited):
    values = _environment(audited)
    values[mcp_server.CATALOG_VARIABLE] = "junos"
    with pytest.raises(mcp_server.ConfigurationError) as error:
        mcp_server.configure(values)
    message = str(error.value)
    assert "junos" in message
    assert PLATFORM in message


def test_configure_rejects_an_unreadable_suppression_file(audited, tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{}", encoding="utf-8")
    with pytest.raises(mcp_server.ConfigurationError) as error:
        mcp_server.configure(_environment(audited, broken))
    assert mcp_server.SUPPRESSIONS_VARIABLE in str(error.value)


def test_configure_accepts_the_full_environment(suppressed):
    current = mcp_server.configuration()
    assert current.tenant == TENANT
    assert current.platform == PLATFORM
    assert current.store_path == suppressed.audited.path
    assert current.suppressions_path == suppressed.path
    assert len(current.rules) == len(load_catalog(PLATFORM))
    assert len(mcp_server.suppressions()) == 1


def test_tools_refuse_to_answer_before_configuration():
    calls = (
        lambda: mcp_server.audit_status(),
        lambda: mcp_server.list_rules(),
        lambda: mcp_server.rule_detail("fortios.ref.dangling"),
        lambda: mcp_server.list_findings(DEVICE),
        lambda: mcp_server.finding_detail(DEVICE, "0" * 64),
        lambda: mcp_server.compare(DEVICE, 1, 2),
    )
    for call in calls:
        with pytest.raises(mcp_server.ConfigurationError) as error:
            call()
        assert mcp_server.STORE_VARIABLE in str(error.value)


def test_main_reports_the_missing_configuration_and_does_not_serve(monkeypatch, capsys):
    served = []
    monkeypatch.setattr(mcp_server.mcp, "run", lambda *args, **keywords: served.append(True))
    for name in mcp_server.REQUIRED_VARIABLES + (mcp_server.SUPPRESSIONS_VARIABLE,):
        monkeypatch.delenv(name, raising=False)
    assert mcp_server.main() == mcp_server.EXIT_ERROR
    assert served == []
    message = capsys.readouterr().err
    for name in mcp_server.REQUIRED_VARIABLES:
        assert name in message


def test_main_configures_before_it_serves(audited, monkeypatch):
    served = []
    monkeypatch.setattr(mcp_server.mcp, "run", lambda *args, **keywords: served.append(True))
    for name, value in _environment(audited).items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(mcp_server.SUPPRESSIONS_VARIABLE, raising=False)
    assert mcp_server.main() == mcp_server.EXIT_OK
    assert served == [True]
    assert mcp_server.configuration().store_path == audited.path


def test_the_server_offers_a_catalog_for_both_platforms():
    assert mcp_server.available_platforms() == ("exos", "fortios")


def test_configure_accepts_the_exos_catalog(audited):
    values = _environment(audited)
    values[mcp_server.CATALOG_VARIABLE] = "exos"
    mcp_server.configure(values)
    current = mcp_server.configuration()
    assert current.platform == "exos"
    assert [rule.id for rule in current.rules] == [
        "exos.snmp.default-community",
        "exos.mgmt.telnet-enabled",
        "exos.logging.no-syslog-target",
        "exos.time.no-sntp-client",
    ]
