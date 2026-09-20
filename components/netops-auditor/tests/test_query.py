import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from netops_auditor import checks_fortios
from netops_auditor import query
from netops_auditor.engine import Rule, load_catalog
from netops_auditor.findings import Finding
from netops_auditor.state import STATE_GONE, STATE_NEW, STATE_OPEN_KNOWN, STATE_SUPPRESSED
from netops_auditor.store import Store
from netops_auditor.suppressions import Suppression

TENANT = "tenant-a"
OTHER_TENANT = "tenant-b"
DEVICE = "fw-a.example.invalid"
SECOND_DEVICE = "fw-b.example.invalid"
THIRD_DEVICE = "fw-c.example.invalid"

SNAPSHOT = "a" * 64
RULES_VERSION = "fortios:12:%s" % ("b" * 64)

CANARY_SOURCE = "snapshots/CANARY-SOURCE-5c7d93/2026-09-12.conf"
CANARY_EVIDENCE = "CANARY-EVIDENCE-8f2b41"
OTHER_CANARY = "CANARY-OTHER-TENANT-3e9a70"

NOW = datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone.utc)
RUN_ONE_AT = "2026-09-11T06:00:00Z"
RUN_TWO_AT = "2026-09-12T06:00:00Z"
OLD_RUN_AT = "2026-09-10T06:00:00Z"

RULE_DANGLING = "fortios.ref.dangling"
RULE_UNUSED = "fortios.obj.unused"
RULE_ANY = "fortios.policy.any-any"
RULE_WAN = "fortios.mgmt.wan-admin-access"

OBJECT_CORP = "firewall address/CORP-NET"
OBJECT_POLICY = "firewall policy/1"
OBJECT_WAN = "system interface/wan1"
OBJECT_FOREIGN = "firewall policy/9"

FORBIDDEN_KEYS = frozenset(
    (
        "config",
        "configuration",
        "raw",
        "text",
        "body",
        "content",
        "lines",
        "source",
        "snapshot_source",
        "snapshot",
        "request",
    )
)


def make_finding(
    rule_id=RULE_DANGLING,
    object_key=OBJECT_POLICY,
    severity="high",
    device=DEVICE,
    rule_version=1,
    evidence=(("attribute", "srcaddr"), ("value", "192.0.2.0/24")),
    section="firewall policy",
    line=12,
    tenant=TENANT,
):
    return Finding(
        rule_id=rule_id,
        rule_version=rule_version,
        tenant=tenant,
        device=device,
        object_key=object_key,
        severity=severity,
        rule_class="fakt",
        section=section,
        line=line,
        evidence=evidence,
    )


def record(
    store,
    findings=(),
    tenant=TENANT,
    device=DEVICE,
    started_at=RUN_TWO_AT,
    source=CANARY_SOURCE,
    sha=SNAPSHOT,
    rules_version=RULES_VERSION,
):
    return store.record_run(tenant, device, sha, source, rules_version, findings, started_at=started_at)


def channel_event(device=SECOND_DEVICE, outcome="failed"):
    return SimpleNamespace(
        device=device,
        channel="ssh",
        request="show full-configuration",
        response_sha256="c" * 64,
        response_bytes=0,
        started_at="2026-09-12T05:00:00Z",
        finished_at="2026-09-12T05:00:10Z",
        outcome=outcome,
    )


def suppression(finding, expires=None, device=DEVICE, author="radek", reason="ticket NET-1"):
    return Suppression(
        fingerprint=finding.fingerprint(),
        rule_id=finding.rule_id,
        rule_version=finding.rule_version,
        tenant=finding.tenant,
        device=device,
        object_key=finding.object_key,
        reason=reason,
        author=author,
        created=NOW - timedelta(days=1),
        expires=NOW + timedelta(days=7) if expires is None else expires,
    )


def make_rule(
    rule_id=RULE_DANGLING,
    version=1,
    severity="high",
    rule_class="fakt",
    title="A policy references an object the configuration does not define.",
    remediation="Define the object or repoint the policy.",
    refs=("https://example.invalid/handbook",),
    known_false_positives="Over the output of show the built-in objects are missing.",
    evidence_fields=("policy", "attribute", "value"),
):
    return Rule(
        id=rule_id,
        version=version,
        check="dangling_reference",
        rule_class=rule_class,
        severity=severity,
        evidence_fields=evidence_fields,
        title=title,
        remediation=remediation,
        refs=refs,
        known_false_positives=known_false_positives,
    )


def blob(value):
    return json.dumps(value, sort_keys=True, default=str)


def collected_keys(value, found=None):
    if found is None:
        found = set()
    if isinstance(value, dict):
        found.update(value)
        for item in value.values():
            collected_keys(item, found)
    elif isinstance(value, (tuple, list)):
        for item in value:
            collected_keys(item, found)
    return found


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "audit.db") as opened:
        yield opened


@pytest.fixture
def populated(tmp_path):
    path = tmp_path / "audit.db"
    opened = Store(path)
    kept = make_finding(rule_id=RULE_DANGLING, object_key=OBJECT_POLICY, severity="high")
    left = make_finding(
        rule_id=RULE_WAN,
        object_key=OBJECT_WAN,
        severity="medium",
        section="system interface",
        line=40,
        evidence=(("interface", "wan1"), ("services", "https ssh")),
    )
    first = record(opened, (kept, left), started_at=RUN_ONE_AT)
    opened.accept_baseline(TENANT, DEVICE, first, "radek", "prevzato pri zavedeni", accepted_at=RUN_ONE_AT)
    canary = make_finding(
        rule_id=RULE_DANGLING,
        object_key=OBJECT_CORP,
        severity="high",
        section="firewall address",
        line=100,
        evidence=(("attribute", "member"), ("value", CANARY_EVIDENCE)),
    )
    unused = make_finding(
        rule_id=RULE_UNUSED,
        object_key=OBJECT_CORP,
        severity="low",
        section="firewall address",
        line=100,
        evidence=(("value", "198.51.100.0/24"),),
    )
    loose = make_finding(
        rule_id=RULE_ANY,
        object_key=OBJECT_CORP,
        severity="medium",
        section="firewall address",
        line=100,
        evidence=(("value", "203.0.113.0/24"),),
    )
    second = record(opened, (kept, canary, unused, loose), started_at=RUN_TWO_AT)
    opened.record_channel_events(TENANT, SECOND_DEVICE, (channel_event(),))
    stranger = make_finding(
        rule_id=RULE_DANGLING,
        object_key=OBJECT_FOREIGN,
        severity="high",
        evidence=(("attribute", "dstaddr"), ("value", OTHER_CANARY)),
        tenant=OTHER_TENANT,
    )
    foreign = record(opened, (stranger,), tenant=OTHER_TENANT, started_at=RUN_TWO_AT)
    yield SimpleNamespace(
        store=opened,
        path=path,
        first=first,
        second=second,
        foreign=foreign,
        kept=kept,
        left=left,
        canary=canary,
        unused=unused,
        loose=loose,
        stranger=stranger,
    )
    opened.close()


def every_result(data, suppressions=()):
    return (
        query.audit_status(data.store, TENANT, now=NOW),
        query.audit_status(data.store, TENANT, device=DEVICE, now=NOW),
        query.list_rules((make_rule(),)),
        query.rule_detail((make_rule(),), RULE_DANGLING),
        query.list_findings(data.store, TENANT, DEVICE, suppressions=suppressions, now=NOW),
        query.list_findings(
            data.store, TENANT, DEVICE, suppressions=suppressions, now=NOW, group_by="object"
        ),
        query.list_findings(data.store, TENANT, DEVICE, now=NOW, severity="low"),
        query.list_findings(data.store, TENANT, DEVICE, now=NOW, state=STATE_GONE),
        query.list_findings(data.store, TENANT, SECOND_DEVICE, now=NOW),
        query.finding_detail(
            data.store, TENANT, DEVICE, data.canary.fingerprint(), suppressions=suppressions, now=NOW
        ),
        query.finding_detail(data.store, TENANT, DEVICE, data.kept.fingerprint(), now=NOW),
        query.compare(data.store, TENANT, DEVICE, data.first, data.second),
    )


def test_device_without_a_run_is_a_finding_not_an_empty_row(store):
    report = query.audit_status(store, TENANT, device=DEVICE, now=NOW)
    assert report["totals"] == {"devices": 1, "fresh": 0, "stale": 0, "never": 1}
    assert report["never_audited"] == (DEVICE,)
    item = report["devices"][0]
    assert item["device"] == DEVICE
    assert item["state"] == query.STATUS_NEVER
    assert item["last_audit"] is None
    assert item["age_hours"] is None
    assert item["run_id"] is None
    assert item["findings_total"] == 0
    assert item["severity_counts"] == {"high": 0, "medium": 0, "low": 0, "info": 0}
    assert item["state_counts"] == {
        STATE_NEW: 0,
        STATE_OPEN_KNOWN: 0,
        STATE_SUPPRESSED: 0,
        STATE_GONE: 0,
    }


def test_device_that_only_failed_collection_is_never_audited_in_the_overview(populated):
    report = query.audit_status(populated.store, TENANT, now=NOW)
    assert tuple(item["device"] for item in report["devices"]) == (DEVICE, SECOND_DEVICE)
    assert report["never_audited"] == (SECOND_DEVICE,)
    assert report["totals"] == {"devices": 2, "fresh": 1, "stale": 0, "never": 1}


def test_audit_status_counts_severities_and_states_of_the_last_run(populated):
    report = query.audit_status(populated.store, TENANT, device=DEVICE, now=NOW)
    item = report["devices"][0]
    assert item["run_id"] == populated.second
    assert item["last_audit"] == RUN_TWO_AT
    assert item["age_hours"] == 6.0
    assert item["state"] == query.STATUS_FRESH
    assert item["findings_total"] == 4
    assert item["severity_counts"] == {"high": 2, "medium": 1, "low": 1, "info": 0}
    assert item["state_counts"] == {
        STATE_NEW: 3,
        STATE_OPEN_KNOWN: 1,
        STATE_SUPPRESSED: 0,
        STATE_GONE: 1,
    }


def test_audit_status_marks_an_old_run_as_stale(store):
    record(store, (make_finding(),), started_at=OLD_RUN_AT)
    report = query.audit_status(store, TENANT, device=DEVICE, now=NOW)
    item = report["devices"][0]
    assert item["age_hours"] == 54.0
    assert item["state"] == query.STATUS_STALE
    assert report["totals"] == {"devices": 1, "fresh": 0, "stale": 1, "never": 0}


def test_audit_status_honours_the_stale_window(store):
    record(store, (), started_at=OLD_RUN_AT)
    fresh = query.audit_status(store, TENANT, device=DEVICE, now=NOW, stale_after_hours=72.0)
    assert fresh["devices"][0]["state"] == query.STATUS_FRESH
    assert fresh["stale_after_hours"] == 72.0
    stale = query.audit_status(store, TENANT, device=DEVICE, now=NOW, stale_after_hours=1.0)
    assert stale["devices"][0]["state"] == query.STATUS_STALE


def test_audit_status_returns_only_the_whitelisted_fields(populated):
    report = query.audit_status(populated.store, TENANT, now=NOW)
    assert set(report) == set(query.STATUS_KEYS)
    assert set(report["totals"]) == set(query.TOTALS_KEYS)
    for item in report["devices"]:
        assert set(item) == set(query.DEVICE_STATUS_KEYS)


def test_audit_status_does_not_cross_tenants(populated):
    ours = query.audit_status(populated.store, TENANT, now=NOW)
    assert tuple(item["device"] for item in ours["devices"]) == (DEVICE, SECOND_DEVICE)
    assert OTHER_CANARY not in blob(ours)
    theirs = query.audit_status(populated.store, OTHER_TENANT, now=NOW)
    assert tuple(item["device"] for item in theirs["devices"]) == (DEVICE,)
    assert theirs["devices"][0]["findings_total"] == 1
    assert theirs["devices"][0]["run_id"] == populated.foreign
    unknown = query.audit_status(populated.store, TENANT, device=THIRD_DEVICE, now=NOW)
    assert unknown["never_audited"] == (THIRD_DEVICE,)


def test_audit_status_needs_a_tenant_and_a_clock(populated):
    with pytest.raises(query.QueryError):
        query.audit_status(populated.store, "", now=NOW)
    with pytest.raises(query.QueryError):
        query.audit_status(populated.store, None, now=NOW)
    with pytest.raises(query.QueryError):
        query.audit_status(populated.store, TENANT)
    with pytest.raises(query.QueryError):
        query.audit_status(populated.store, TENANT, now=datetime(2026, 9, 12, 12, 0, 0))
    with pytest.raises(query.QueryError):
        query.audit_status(populated.store, TENANT, now=NOW, stale_after_hours=0)


def test_list_rules_returns_the_catalog_card_and_nothing_else():
    rules = (make_rule(rule_id=RULE_UNUSED, severity="low"), make_rule(rule_id=RULE_DANGLING))
    listed = query.list_rules(rules)
    assert tuple(item["id"] for item in listed) == (RULE_UNUSED, RULE_DANGLING)
    for item in listed:
        assert set(item) == set(query.RULE_KEYS)
    assert listed[0]["severity"] == "low"
    dangling = listed[1]
    assert dangling["version"] == 1
    assert dangling["class"] == "fakt"
    assert dangling["severity"] == "high"
    assert dangling["refs"] == ("https://example.invalid/handbook",)


def test_list_rules_of_an_empty_catalog_is_empty():
    assert query.list_rules(()) == ()


def test_rule_detail_adds_remediation_false_positives_and_evidence_fields():
    detail = query.rule_detail((make_rule(),), RULE_DANGLING)
    assert set(detail) == set(query.RULE_DETAIL_KEYS)
    assert detail["remediation"] == "Define the object or repoint the policy."
    assert detail["known_false_positives"].startswith("Over the output of show")
    assert detail["evidence_fields"] == ("policy", "attribute", "value")


def test_rule_detail_of_an_unknown_rule_is_an_error():
    with pytest.raises(query.QueryError):
        query.rule_detail((make_rule(),), "fortios.nothing.here")
    with pytest.raises(query.QueryError):
        query.rule_detail((make_rule(),), "")


def test_the_shipped_catalog_passes_the_same_whitelist():
    assert checks_fortios is not None
    rules = load_catalog("fortios")
    listed = query.list_rules(rules)
    assert len(listed) == len(rules)
    for item in listed:
        assert set(item) == set(query.RULE_KEYS)
        detail = query.rule_detail(rules, item["id"])
        assert set(detail) == set(query.RULE_DETAIL_KEYS)
        assert detail["title"]
        assert detail["remediation"]


def test_list_findings_computes_every_state(populated):
    listing = query.list_findings(
        populated.store,
        TENANT,
        DEVICE,
        suppressions=(suppression(populated.loose),),
        now=NOW,
    )
    assert listing["run_state"] == query.RUN_PRESENT
    assert listing["run_id"] == populated.second
    assert listing["started_at"] == RUN_TWO_AT
    states = {item["fingerprint"]: item["state"] for item in listing["findings"]}
    assert states[populated.kept.fingerprint()] == STATE_OPEN_KNOWN
    assert states[populated.canary.fingerprint()] == STATE_NEW
    assert states[populated.unused.fingerprint()] == STATE_NEW
    assert states[populated.loose.fingerprint()] == STATE_SUPPRESSED
    assert tuple(item["fingerprint"] for item in listing["gone"]) == (populated.left.fingerprint(),)
    assert listing["gone"][0]["state"] == STATE_GONE
    assert listing["counts"] == {
        STATE_NEW: 2,
        STATE_OPEN_KNOWN: 1,
        STATE_SUPPRESSED: 1,
        STATE_GONE: 1,
    }
    assert listing["total"] == 5


def test_list_findings_returns_only_the_whitelisted_fields(populated):
    listing = query.list_findings(
        populated.store,
        TENANT,
        DEVICE,
        suppressions=(suppression(populated.loose),),
        now=NOW,
        group_by="object",
    )
    assert set(listing) == set(query.LISTING_KEYS)
    for item in listing["findings"]:
        assert set(item) == set(query.FINDING_KEYS)
    for item in listing["gone"]:
        assert set(item) == set(query.GONE_KEYS)
    for item in listing["groups"]:
        assert set(item) == set(query.GROUP_KEYS)


def test_list_findings_keeps_a_stable_order(populated):
    first = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, group_by="object")
    second = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, group_by="object")
    assert first == second
    assert blob(first) == blob(second)
    assert tuple(item["rule_id"] for item in first["findings"]) == (
        RULE_UNUSED,
        RULE_ANY,
        RULE_DANGLING,
        RULE_DANGLING,
    )
    assert tuple(item["object_key"] for item in first["findings"]) == (
        OBJECT_CORP,
        OBJECT_CORP,
        OBJECT_CORP,
        OBJECT_POLICY,
    )


def test_group_by_object_makes_one_problem_out_of_many_findings(populated):
    listing = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, group_by="object")
    groups = listing["groups"]
    assert tuple(item["object_key"] for item in groups) == (OBJECT_CORP, OBJECT_POLICY, OBJECT_WAN)
    assert tuple(item["count"] for item in groups) == (3, 1, 1)
    biggest = groups[0]
    assert biggest["severity"] == "high"
    assert biggest["rule_ids"] == tuple(sorted((RULE_DANGLING, RULE_UNUSED, RULE_ANY)))
    assert biggest["states"] == (STATE_NEW,)
    assert biggest["fingerprints"] == tuple(
        sorted(
            (
                populated.canary.fingerprint(),
                populated.unused.fingerprint(),
                populated.loose.fingerprint(),
            )
        )
    )
    assert groups[2]["states"] == (STATE_GONE,)


def test_without_group_by_there_are_no_groups(populated):
    listing = query.list_findings(populated.store, TENANT, DEVICE, now=NOW)
    assert listing["groups"] == ()
    with pytest.raises(query.QueryError):
        query.list_findings(populated.store, TENANT, DEVICE, now=NOW, group_by="rule")


def test_severity_filter_narrows_findings_and_counts(populated):
    listing = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, severity="low")
    assert tuple(item["fingerprint"] for item in listing["findings"]) == (
        populated.unused.fingerprint(),
    )
    assert listing["gone"] == ()
    assert listing["total"] == 1
    assert listing["counts"] == {
        STATE_NEW: 1,
        STATE_OPEN_KNOWN: 0,
        STATE_SUPPRESSED: 0,
        STATE_GONE: 0,
    }
    with pytest.raises(query.QueryError):
        query.list_findings(populated.store, TENANT, DEVICE, now=NOW, severity="critical")


def test_state_filter_can_ask_for_what_disappeared(populated):
    listing = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, state=STATE_GONE)
    assert listing["findings"] == ()
    assert tuple(item["fingerprint"] for item in listing["gone"]) == (populated.left.fingerprint(),)
    assert listing["total"] == 1
    known = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, state=STATE_OPEN_KNOWN)
    assert tuple(item["fingerprint"] for item in known["findings"]) == (
        populated.kept.fingerprint(),
    )
    with pytest.raises(query.QueryError):
        query.list_findings(populated.store, TENANT, DEVICE, now=NOW, state="unknown")


def test_since_does_not_return_older_runs(populated):
    kept = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, since=RUN_ONE_AT)
    assert kept["run_state"] == query.RUN_PRESENT
    assert kept["run_id"] == populated.second
    hidden = query.list_findings(
        populated.store, TENANT, DEVICE, now=NOW, since="2026-09-12T07:00:00Z"
    )
    assert hidden["run_state"] == query.RUN_BEFORE_SINCE
    assert hidden["run_id"] is None
    assert hidden["findings"] == ()
    assert hidden["gone"] == ()
    assert hidden["total"] == 0
    assert set(hidden) == set(query.LISTING_KEYS)
    with pytest.raises(query.QueryError):
        query.list_findings(populated.store, TENANT, DEVICE, now=NOW, since="12. 9. 2026")


def test_list_findings_of_a_device_without_a_run_says_so(populated):
    listing = query.list_findings(populated.store, TENANT, SECOND_DEVICE, now=NOW)
    assert listing["run_state"] == query.RUN_NEVER
    assert listing["run_id"] is None
    assert listing["findings"] == ()
    assert listing["gone"] == ()
    assert listing["groups"] == ()
    assert listing["counts"] == {
        STATE_NEW: 0,
        STATE_OPEN_KNOWN: 0,
        STATE_SUPPRESSED: 0,
        STATE_GONE: 0,
    }
    assert set(listing) == set(query.LISTING_KEYS)


def test_a_run_without_findings_is_a_clean_listing(store):
    record(store, (), started_at=RUN_TWO_AT)
    listing = query.list_findings(store, TENANT, DEVICE, now=NOW, group_by="object")
    assert listing["run_state"] == query.RUN_PRESENT
    assert listing["total"] == 0
    assert listing["findings"] == ()
    assert listing["gone"] == ()
    assert listing["groups"] == ()


def test_empty_baseline_makes_every_finding_new(store):
    finding = make_finding()
    record(store, (finding,), started_at=RUN_TWO_AT)
    listing = query.list_findings(store, TENANT, DEVICE, now=NOW)
    assert listing["findings"][0]["state"] == STATE_NEW
    assert listing["counts"][STATE_NEW] == 1


def test_list_findings_does_not_cross_tenants(populated):
    ours = query.list_findings(populated.store, TENANT, DEVICE, now=NOW)
    fingerprints = tuple(item["fingerprint"] for item in ours["findings"])
    assert populated.stranger.fingerprint() not in fingerprints
    assert OTHER_CANARY not in blob(ours)
    assert ours["run_id"] == populated.second
    theirs = query.list_findings(populated.store, OTHER_TENANT, DEVICE, now=NOW)
    assert theirs["run_id"] == populated.foreign
    assert theirs["total"] == 1
    assert CANARY_EVIDENCE not in blob(theirs)


def test_a_suppression_of_another_device_does_not_silence_this_one(populated):
    foreign = suppression(populated.loose, device=SECOND_DEVICE)
    listing = query.list_findings(
        populated.store, TENANT, DEVICE, suppressions=(foreign,), now=NOW
    )
    states = {item["fingerprint"]: item["state"] for item in listing["findings"]}
    assert states[populated.loose.fingerprint()] == STATE_NEW
    assert listing["counts"][STATE_SUPPRESSED] == 0


def test_an_expired_suppression_does_not_silence_a_finding(populated):
    stale = suppression(populated.loose, expires=NOW - timedelta(hours=1))
    listing = query.list_findings(populated.store, TENANT, DEVICE, suppressions=(stale,), now=NOW)
    states = {item["fingerprint"]: item["state"] for item in listing["findings"]}
    assert states[populated.loose.fingerprint()] == STATE_NEW


def test_list_findings_needs_a_tenant_a_device_and_a_clock(populated):
    with pytest.raises(query.QueryError):
        query.list_findings(populated.store, "", DEVICE, now=NOW)
    with pytest.raises(query.QueryError):
        query.list_findings(populated.store, TENANT, "", now=NOW)
    with pytest.raises(query.QueryError):
        query.list_findings(populated.store, TENANT, DEVICE)


def test_finding_detail_carries_the_baseline_record(populated):
    detail = query.finding_detail(populated.store, TENANT, DEVICE, populated.kept.fingerprint(), now=NOW)
    assert set(detail) == set(query.DETAIL_KEYS)
    assert detail["tenant"] == TENANT
    assert detail["device"] == DEVICE
    assert detail["run_id"] == populated.second
    assert detail["started_at"] == RUN_TWO_AT
    assert detail["state"] == STATE_OPEN_KNOWN
    assert detail["object_key"] == OBJECT_POLICY
    assert detail["suppression"] is None
    assert set(detail["baseline"]) == set(query.BASELINE_KEYS)
    assert detail["baseline"]["accepted_by"] == "radek"
    assert detail["baseline"]["accepted_at"] == RUN_ONE_AT
    assert detail["baseline"]["run_id"] == populated.first


def test_finding_detail_carries_the_suppression_and_its_validity(populated):
    active = suppression(populated.loose)
    detail = query.finding_detail(
        populated.store,
        TENANT,
        DEVICE,
        populated.loose.fingerprint(),
        suppressions=(active,),
        now=NOW,
    )
    assert set(detail["suppression"]) == set(query.SUPPRESSION_KEYS)
    assert detail["suppression"]["author"] == "radek"
    assert detail["suppression"]["reason"] == "ticket NET-1"
    assert detail["suppression"]["expires"] == "2026-09-19T12:00:00Z"
    assert detail["suppression"]["active"] is True
    assert detail["state"] == STATE_SUPPRESSED
    assert detail["baseline"] is None
    later = query.finding_detail(
        populated.store,
        TENANT,
        DEVICE,
        populated.loose.fingerprint(),
        suppressions=(active,),
        now=NOW + timedelta(days=30),
    )
    assert later["suppression"]["active"] is False
    assert later["state"] == STATE_NEW


def test_finding_detail_of_something_absent_is_none(populated, store):
    assert query.finding_detail(populated.store, TENANT, DEVICE, "0" * 64, now=NOW) is None
    assert query.finding_detail(populated.store, TENANT, SECOND_DEVICE, populated.kept.fingerprint(), now=NOW) is None
    assert query.finding_detail(store, TENANT, DEVICE, "0" * 64, now=NOW) is None


def test_finding_detail_does_not_cross_tenants(populated):
    assert (
        query.finding_detail(populated.store, TENANT, DEVICE, populated.stranger.fingerprint(), now=NOW)
        is None
    )
    theirs = query.finding_detail(
        populated.store, OTHER_TENANT, DEVICE, populated.stranger.fingerprint(), now=NOW
    )
    assert theirs["evidence"]["value"] == OTHER_CANARY
    assert theirs["run_id"] == populated.foreign
    mine = query.finding_detail(
        populated.store, TENANT, DEVICE, populated.kept.fingerprint(), now=NOW
    )
    assert mine["run_id"] == populated.second
    assert mine["evidence"]["value"] == "192.0.2.0/24"
    assert (
        query.finding_detail(populated.store, OTHER_TENANT, DEVICE, populated.canary.fingerprint(), now=NOW)
        is None
    )


def test_compare_reports_what_came_what_went_and_what_stayed(populated):
    result = query.compare(populated.store, TENANT, DEVICE, populated.first, populated.second)
    assert set(result) == set(query.COMPARE_KEYS)
    assert set(result["counts"]) == set(query.COMPARE_COUNT_KEYS)
    assert set(result["first"]) == set(query.RUN_KEYS)
    assert set(result["second"]) == set(query.RUN_KEYS)
    for item in result["added"] + result["removed"] + result["kept"]:
        assert set(item) == set(query.COMPARE_ITEM_KEYS)
    assert result["first"]["run_id"] == populated.first
    assert result["first"]["findings_total"] == 2
    assert result["second"]["findings_total"] == 4
    assert result["second"]["rules_version"] == RULES_VERSION
    assert result["second"]["snapshot_sha256"] == SNAPSHOT
    assert tuple(item["fingerprint"] for item in result["added"]) == tuple(
        item["fingerprint"]
        for item in sorted(
            (
                {"fingerprint": populated.canary.fingerprint(), "rule_id": RULE_DANGLING, "object_key": OBJECT_CORP},
                {"fingerprint": populated.loose.fingerprint(), "rule_id": RULE_ANY, "object_key": OBJECT_CORP},
                {"fingerprint": populated.unused.fingerprint(), "rule_id": RULE_UNUSED, "object_key": OBJECT_CORP},
            ),
            key=lambda item: (item["rule_id"], item["object_key"], item["fingerprint"]),
        )
    )
    assert tuple(item["fingerprint"] for item in result["removed"]) == (populated.left.fingerprint(),)
    assert tuple(item["fingerprint"] for item in result["kept"]) == (populated.kept.fingerprint(),)
    assert result["counts"] == {"added": 3, "removed": 1, "kept": 1}


def test_compare_of_a_run_with_itself_changes_nothing(populated):
    result = query.compare(populated.store, TENANT, DEVICE, populated.second, populated.second)
    assert result["added"] == ()
    assert result["removed"] == ()
    assert result["counts"] == {"added": 0, "removed": 0, "kept": 4}


def test_compare_refuses_a_run_of_another_tenant_or_device(populated):
    with pytest.raises(query.QueryError):
        query.compare(populated.store, TENANT, DEVICE, populated.first, populated.foreign)
    with pytest.raises(query.QueryError):
        query.compare(populated.store, OTHER_TENANT, DEVICE, populated.foreign, populated.second)
    with pytest.raises(query.QueryError):
        query.compare(populated.store, TENANT, SECOND_DEVICE, populated.first, populated.second)
    with pytest.raises(query.QueryError):
        query.compare(populated.store, TENANT, DEVICE, populated.first, 9999)
    with pytest.raises(query.QueryError):
        query.compare(populated.store, "", DEVICE, populated.first, populated.second)


def test_canary_evidence_appears_only_where_evidence_belongs(populated):
    listing = query.list_findings(populated.store, TENANT, DEVICE, now=NOW)
    carrier = [item for item in listing["findings"] if item["fingerprint"] == populated.canary.fingerprint()]
    assert carrier[0]["evidence"] == {"attribute": "member", "value": CANARY_EVIDENCE}
    detail = query.finding_detail(populated.store, TENANT, DEVICE, populated.canary.fingerprint(), now=NOW)
    assert detail["evidence"]["value"] == CANARY_EVIDENCE
    grouped = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, group_by="object")
    silent = (
        query.audit_status(populated.store, TENANT, now=NOW),
        query.audit_status(populated.store, TENANT, device=DEVICE, now=NOW),
        query.list_rules(load_catalog("fortios")),
        query.rule_detail(load_catalog("fortios"), "fortios.ref.dangling"),
        query.compare(populated.store, TENANT, DEVICE, populated.first, populated.second),
        grouped["groups"],
        query.list_findings(populated.store, TENANT, DEVICE, now=NOW, severity="low"),
        query.list_findings(populated.store, TENANT, DEVICE, now=NOW, state=STATE_GONE),
        query.finding_detail(populated.store, TENANT, DEVICE, populated.kept.fingerprint(), now=NOW),
    )
    for result in silent:
        assert CANARY_EVIDENCE not in blob(result)


def test_no_function_returns_a_configuration_field(populated):
    for result in every_result(populated, suppressions=(suppression(populated.loose),)):
        assert not collected_keys(result) & FORBIDDEN_KEYS
        assert CANARY_SOURCE not in blob(result)
        assert "CANARY-SOURCE" not in blob(result)


def test_evidence_holds_only_scalars_that_the_store_carried(populated):
    listing = query.list_findings(populated.store, TENANT, DEVICE, now=NOW)
    for item in listing["findings"]:
        assert isinstance(item["evidence"], dict)
        for key, value in item["evidence"].items():
            assert isinstance(key, str)
            assert isinstance(value, (str, int, bool))


def test_no_query_writes_to_the_database(populated):
    before = digest(populated.path)
    before_files = sorted(item.name for item in populated.path.parent.iterdir())
    every_result(populated, suppressions=(suppression(populated.loose),))
    assert digest(populated.path) == before
    assert sorted(item.name for item in populated.path.parent.iterdir()) == before_files


def test_the_database_file_is_unchanged_after_the_store_is_closed(populated):
    before = digest(populated.path)
    every_result(populated, suppressions=(suppression(populated.loose),))
    populated.store.close()
    assert digest(populated.path) == before


def test_baseline_and_suppressions_stay_untouched(populated):
    every_result(populated, suppressions=(suppression(populated.loose),))
    assert populated.store.baseline_fingerprints(TENANT, DEVICE) == frozenset(
        (populated.kept.fingerprint(), populated.left.fingerprint())
    )
    assert len(populated.store.runs_for_device(TENANT, DEVICE)) == 2
    assert len(populated.store.findings_for_run(TENANT, populated.second)) == 4


def test_every_function_survives_an_empty_store(store):
    overview = query.audit_status(store, TENANT, now=NOW)
    assert overview["devices"] == ()
    assert overview["never_audited"] == ()
    assert overview["totals"] == {"devices": 0, "fresh": 0, "stale": 0, "never": 0}
    assert set(overview) == set(query.STATUS_KEYS)
    single = query.audit_status(store, TENANT, device=DEVICE, now=NOW)
    assert single["totals"]["never"] == 1
    listing = query.list_findings(store, TENANT, DEVICE, now=NOW, group_by="object")
    assert listing["run_state"] == query.RUN_NEVER
    assert query.finding_detail(store, TENANT, DEVICE, "0" * 64, now=NOW) is None
    assert query.list_rules(()) == ()
    with pytest.raises(query.QueryError):
        query.compare(store, TENANT, DEVICE, 1, 2)
