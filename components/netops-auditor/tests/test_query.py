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


def suppression(finding, expires=None, device=DEVICE, author="operator", reason="ticket NET-1"):
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
    opened.accept_baseline(TENANT, DEVICE, first, "operator", "accepted at rollout", accepted_at=RUN_ONE_AT)
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
    assert detail["baseline"]["accepted_by"] == "operator"
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
    assert detail["suppression"]["author"] == "operator"
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


def test_a_carried_finding_detail_points_at_the_run_that_stores_it(store):
    optional = "exos.port.optional"
    skipped = {optional: {"status": "not-evaluated", "reason": "no-vlan-content", "required": False}}
    evaluated = {optional: {"status": "evaluated", "reason": "", "required": False}}
    finding = make_finding(rule_id=optional, object_key="port/1:1")
    first = store.record_run(
        TENANT, DEVICE, SNAPSHOT, CANARY_SOURCE, RULES_VERSION, [finding],
        started_at="2026-09-09T06:00:00Z", rule_status=evaluated,
    )
    for moment in ("2026-09-10T06:00:00Z", "2026-09-11T06:00:00Z"):
        store.record_run(
            TENANT, DEVICE, SNAPSHOT, CANARY_SOURCE, RULES_VERSION, [],
            started_at=moment, rule_status=skipped,
        )
    fingerprint = finding.fingerprint()
    detail = query.finding_detail(store, TENANT, DEVICE, fingerprint, now=NOW)
    assert detail["state"] == "not-evaluated"
    assert (detail["run_id"], detail["started_at"]) == (first, "2026-09-09T06:00:00Z")
    incomplete = {"exos.snapshot.incomplete": {"status": "evaluated", "reason": "", "required": True}}
    store.record_run(
        TENANT, DEVICE, SNAPSHOT, CANARY_SOURCE, RULES_VERSION,
        [make_finding(rule_id="exos.snapshot.incomplete", object_key="snapshot")],
        started_at="2026-09-12T06:00:00Z", rule_status=incomplete,
    )
    detail = query.finding_detail(store, TENANT, DEVICE, fingerprint, now=NOW)
    assert detail["state"] == "not-evaluated"
    assert (detail["run_id"], detail["started_at"]) == (first, "2026-09-09T06:00:00Z")


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
    # The store is in WAL: fold the committed runs into the file first, so that the digest covers them
    # and a later difference can only come from the queries.
    assert populated.store._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
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


@pytest.mark.parametrize("rule_id",["fortios.snapshot.incomplete","exos.snapshot.incomplete","fortios.scope.vdom-unsupported"])
def test_reciprocal_gate_cannot_resolve_or_accept_baseline(tmp_path, rule_id):
    from netops_auditor.store import StoreError
    with Store(tmp_path / "gate.sqlite") as store:
        original = make_finding()
        first = record(store, findings=(original,), started_at=RUN_ONE_AT)
        blocked = record(store, findings=(make_finding(rule_id=rule_id),), started_at=RUN_TWO_AT)
        with pytest.raises(StoreError):
            store.accept_baseline(TENANT, DEVICE, blocked, "reviewer", "fixture")
        with pytest.raises(query.QueryError):
            query.compare(store, TENANT, DEVICE, first, blocked)
        with pytest.raises(query.QueryError):
            query.compare(store, TENANT, DEVICE, blocked, first)
        assert store.accept_baseline(TENANT, DEVICE, first, "reviewer", "fixture") == 1
        listing = query.list_findings(store, TENANT, DEVICE, now=NOW)
        assert not listing["gone"]
        assert any(f["state"] == "not-evaluated" for f in listing["findings"])


def _metadata_lookups(store, call):
    statements = []
    store._connection.set_trace_callback(statements.append)
    try:
        result = call()
    finally:
        store._connection.set_trace_callback(None)
    return result, [item for item in statements if "FROM runs" in item]


def test_compare_reads_two_runs_by_id_not_the_whole_history(store):
    ids = [
        record(store, (make_finding(object_key="obj/%d" % number),), started_at="2026-09-%02dT06:00:00Z" % (number + 1))
        for number in range(12)
    ]
    other = record(store, (), device=SECOND_DEVICE, started_at="2026-09-20T06:00:00Z")
    result, lookups = _metadata_lookups(store, lambda: query.compare(store, TENANT, DEVICE, ids[7], ids[2]))
    assert len(lookups) <= 2
    assert all("ORDER BY" not in item and "id = " in item for item in lookups)
    assert (result["first"]["run_id"], result["second"]["run_id"]) == (ids[7], ids[2])
    assert result["counts"] == {"added": 1, "removed": 1, "kept": 0}
    same, lookups = _metadata_lookups(store, lambda: query.compare(store, TENANT, DEVICE, ids[3], ids[3]))
    assert same["counts"] == {"added": 0, "removed": 0, "kept": 1}
    for run_id in (9999, other):
        with pytest.raises(query.QueryError):
            query.compare(store, TENANT, DEVICE, ids[0], run_id)
    with pytest.raises(query.QueryError):
        query.compare(store, OTHER_TENANT, DEVICE, ids[0], ids[1])


def _skipped_history(store):
    optional = "exos.port.optional"
    skipped = {optional: {"status": "not-evaluated", "reason": "no-vlan-content", "required": False}}
    evaluated = {optional: {"status": "evaluated", "reason": "", "required": False}}
    carried = make_finding(rule_id=optional, object_key="port/1:1")
    plain = make_finding(rule_id=RULE_DANGLING, object_key=OBJECT_POLICY, severity="high")
    gone = make_finding(rule_id=RULE_WAN, object_key=OBJECT_WAN, severity="medium")
    first = store.record_run(
        TENANT, DEVICE, SNAPSHOT, CANARY_SOURCE, RULES_VERSION, [carried, plain, gone],
        started_at="2026-09-09T06:00:00Z", rule_status=evaluated,
    )
    for moment, found in (("2026-09-10T06:00:00Z", [plain, gone]), ("2026-09-11T06:00:00Z", [plain])):
        store.record_run(
            TENANT, DEVICE, SNAPSHOT, CANARY_SOURCE, RULES_VERSION, found,
            started_at=moment, rule_status=skipped,
        )
    return first, carried, plain, gone


def test_history_is_looked_up_once_per_findings_request(store):
    first, carried, plain, gone = _skipped_history(store)
    calls = []
    original = query.last_evaluated
    query.last_evaluated = lambda *args: calls.append(args) or original(*args)
    try:
        listing = query.list_findings(store, TENANT, DEVICE, now=NOW)
        assert len(calls) == 1
        del calls[:]
        detail = query.finding_detail(store, TENANT, DEVICE, carried.fingerprint(), now=NOW)
        assert len(calls) == 1
        del calls[:]
        query.audit_status(store, TENANT, device=DEVICE, now=NOW)
        assert len(calls) == 1
    finally:
        query.last_evaluated = original
    states = {item["fingerprint"]: item["state"] for item in listing["findings"]}
    states.update({item["fingerprint"]: item["state"] for item in listing["gone"]})
    assert states == {
        plain.fingerprint(): STATE_NEW,
        carried.fingerprint(): "not-evaluated",
        gone.fingerprint(): STATE_GONE,
    }
    assert (detail["state"], detail["run_id"], detail["started_at"]) == (
        "not-evaluated", first, "2026-09-09T06:00:00Z"
    )
    # a later request sees an import finished in between
    later = store.record_run(
        TENANT, DEVICE, SNAPSHOT, CANARY_SOURCE, RULES_VERSION, [plain],
        started_at="2026-09-12T06:00:00Z",
    )
    again = query.list_findings(store, TENANT, DEVICE, now=NOW)
    assert again["run_id"] == later
    assert carried.fingerprint() not in {item["fingerprint"] for item in again["findings"]}


def _legacy_query():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).parent / "support" / "legacy_query_v106.py"
    spec = importlib.util.spec_from_file_location("legacy_query_v106", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _long_skipped_history(store):
    optional = "exos.port.optional"
    other_optional = "exos.port.other"
    skipped = {
        optional: {"status": "not-evaluated", "reason": "no-vlan-content", "required": False},
        other_optional: {"status": "not-evaluated", "reason": "no-stack", "required": False},
    }
    evaluated = {
        optional: {"status": "evaluated", "reason": "", "required": False},
        other_optional: {"status": "evaluated", "reason": "", "required": False},
    }
    carried = make_finding(rule_id=optional, object_key="port/1:1")
    carried_other = make_finding(rule_id=other_optional, object_key="port/2:1")
    plain = make_finding(rule_id=RULE_DANGLING, object_key=OBJECT_POLICY, severity="high")
    muted = make_finding(rule_id=RULE_UNUSED, object_key=OBJECT_CORP, severity="low")
    gone = make_finding(rule_id=RULE_WAN, object_key=OBJECT_WAN, severity="medium")
    runs = [
        store.record_run(
            TENANT, DEVICE, SNAPSHOT, CANARY_SOURCE, RULES_VERSION, found,
            started_at=moment, rule_status=status,
        )
        for moment, found, status in (
            ("2026-09-07T06:00:00Z", [carried, carried_other, plain, muted, gone], evaluated),
            ("2026-09-08T06:00:00Z", [carried_other, plain, muted, gone], {**evaluated, optional: skipped[optional]}),
            ("2026-09-09T06:00:00Z", [plain, muted, gone], skipped),
            ("2026-09-10T06:00:00Z", [plain, muted, gone], skipped),
            ("2026-09-11T06:00:00Z", [plain, muted], {optional: skipped[optional], other_optional: evaluated[other_optional]}),
        )
    ]
    return runs, (carried, carried_other, plain, muted, gone)


def _all_results(module, store, findings, suppressions):
    fingerprints = [item.fingerprint() for item in findings] + ["f" * 64]
    return {
        "listing": module.list_findings(store, TENANT, DEVICE, suppressions=suppressions, now=NOW),
        "detail": [
            module.finding_detail(store, TENANT, DEVICE, value, suppressions=suppressions, now=NOW)
            for value in fingerprints
        ],
        "status": module.audit_status(store, TENANT, now=NOW),
        "device_status": module.audit_status(store, TENANT, device=DEVICE, now=NOW),
    }


def test_single_history_lookup_gives_the_same_results_as_the_v106_path(store):
    legacy = _legacy_query()
    runs, (carried, carried_other, plain, muted, gone) = _long_skipped_history(store)
    record(store, (), device=SECOND_DEVICE, started_at="2026-09-11T07:00:00Z")
    suppressions = (suppression(muted), suppression(plain, device=SECOND_DEVICE))
    findings = (carried, carried_other, plain, muted, gone)
    old = _all_results(legacy, store, findings, suppressions)
    new = _all_results(query, store, findings, suppressions)
    # O4 added coverage to each device; optional skipped rules are not gaps.
    complete = {"complete": True, "inherent_gaps": [], "actionable_gaps": []}
    for key in ("status", "device_status"):
        for device in new[key]["devices"]:
            current = device.pop("coverage")
            counts = current.pop("counts")
            if device["rule_status"]:
                assert sum(counts.values()) == len(device["rule_status"])
            else:
                assert counts is None
            assert current == complete
    assert new == old
    # the fixture really exercises the interesting states
    states = {item["fingerprint"]: item["state"] for item in new["listing"]["findings"]}
    states.update({item["fingerprint"]: item["state"] for item in new["listing"]["gone"]})
    assert states[carried.fingerprint()] == "not-evaluated"
    assert states[muted.fingerprint()] == STATE_SUPPRESSED
    assert states[gone.fingerprint()] == STATE_GONE
    assert new["detail"][0]["state"] == "not-evaluated"
    assert new["detail"][0]["run_id"] == runs[0]
    assert new["detail"][-1] is None
    # carried across several runs: the other rule was evaluated again, so it is not carried
    assert states.get(carried_other.fingerprint()) != "not-evaluated"
    # the old path looked the history up twice per listing, the new one exactly once
    for module, expected in ((legacy, 2), (query, 1)):
        calls = []
        original = module.last_evaluated
        module.last_evaluated = lambda *args: calls.append(args) or original(*args)
        try:
            module.list_findings(store, TENANT, DEVICE, suppressions=suppressions, now=NOW)
        finally:
            module.last_evaluated = original
        assert len(calls) == expected


# --- findings_summary (1.0.9 bod 14) ---------------------------------------------------------

SUMMARY_RULES = (
    make_rule(RULE_DANGLING),
    make_rule(RULE_UNUSED, severity="low"),
    make_rule(RULE_ANY, severity="medium"),
    make_rule(RULE_WAN, severity="medium"),
)

SUMMARY_FILTERS = (
    {},
    {"severity": "high"},
    {"severity": "medium"},
    {"state": STATE_NEW},
    {"state": STATE_GONE},
    {"state": STATE_SUPPRESSED},
    {"state": STATE_OPEN_KNOWN},
    {"severity": "high", "state": STATE_NEW},
    {"severity": "info"},
)


def _third_device(populated):
    third = make_finding(rule_id=RULE_UNUSED, object_key=OBJECT_CORP, severity="low", device=THIRD_DEVICE)
    other = make_finding(rule_id=RULE_DANGLING, object_key=OBJECT_POLICY, severity="high", device=THIRD_DEVICE)
    record(populated.store, (third, other), device=THIRD_DEVICE, started_at=RUN_TWO_AT)
    return third, other


def _summary(populated, **keywords):
    keywords.setdefault("now", NOW)
    return query.findings_summary(populated.store, TENANT, SUMMARY_RULES, **keywords)


def test_findings_summary_matches_the_sum_of_list_findings_over_devices(populated):
    _third_device(populated)
    suppressions = (suppression(populated.loose),)
    devices = (DEVICE, SECOND_DEVICE, THIRD_DEVICE)
    for filters in SUMMARY_FILTERS:
        summary = _summary(populated, suppressions=suppressions, limit=200, **filters)
        listings = [
            query.list_findings(populated.store, TENANT, name, suppressions=suppressions, now=NOW, **filters)
            for name in devices
        ]
        assert summary["total_matching"] == sum(item["total"] for item in listings), filters
        expected = sorted(
            (name, entry["fingerprint"], entry["state"])
            for name, listing in zip(devices, listings)
            for entry in listing["findings"] + listing["gone"]
        )
        assert sorted(
            (item["device"], item["fingerprint"], item["state"]) for item in summary["items"]
        ) == expected, filters
        for state in query.STATES:
            assert summary["counts_after_filter"]["state"][state] == sum(
                item["counts"][state] for item in listings
            ), (filters, state)


def test_findings_summary_rule_id_filter_matches_list_findings(populated):
    _third_device(populated)
    summary = _summary(populated, rule_id=RULE_DANGLING, limit=200)
    expected = 0
    for name in (DEVICE, SECOND_DEVICE, THIRD_DEVICE):
        listing = query.list_findings(populated.store, TENANT, name, now=NOW)
        expected += sum(
            1 for entry in listing["findings"] + listing["gone"] if entry["rule_id"] == RULE_DANGLING
        )
    assert summary["total_matching"] == expected == 3
    assert {item["rule_id"] for item in summary["items"]} == {RULE_DANGLING}


def test_findings_summary_of_one_device_matches_list_findings(populated):
    _third_device(populated)
    summary = _summary(populated, device=DEVICE, state=STATE_NEW)
    listing = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, state=STATE_NEW)
    assert summary["device"] == DEVICE
    assert {item["device"] for item in summary["items"]} == {DEVICE}
    assert summary["total_matching"] == listing["total"] == 3


def test_findings_summary_limit_truncates_and_reports_it(populated):
    _third_device(populated)
    full = _summary(populated)
    assert full["total_matching"] == 7
    assert full["returned"] == 7
    assert full["truncated"] is False
    cut = _summary(populated, limit=3)
    assert cut["total_matching"] == 7
    assert cut["returned"] == len(cut["items"]) == 3
    assert cut["truncated"] is True
    assert cut["items"] == full["items"][:3]
    exact = _summary(populated, limit=7)
    assert exact["truncated"] is False
    assert _summary(populated, limit=query.SUMMARY_LIMIT_MAX)["returned"] == 7
    assert query.SUMMARY_LIMIT_DEFAULT == 50


@pytest.mark.parametrize("limit", [0, -1, 201, 1.5, "10", True, None])
def test_findings_summary_refuses_a_limit_outside_the_range(populated, limit):
    with pytest.raises(query.QueryError, match="limit must be"):
        _summary(populated, limit=limit)


def test_findings_summary_counts_before_and_after_the_filter(populated):
    _third_device(populated)
    summary = _summary(populated, severity="high", state=STATE_NEW)
    before = summary["counts_before_filter"]
    after = summary["counts_after_filter"]
    assert set(before) == set(after) == set(query.SUMMARY_COUNT_KEYS)
    assert set(before["state"]) == set(after["state"]) == set(query.SUMMARY_STATES)
    assert set(before["severity"]) == set(after["severity"]) == {"high", "medium", "low", "info"}
    # every entry of the tenant: DEVICE 4 present + 1 gone, THIRD_DEVICE 2 new
    assert before["state"] == {
        STATE_NEW: 5,
        STATE_OPEN_KNOWN: 1,
        STATE_SUPPRESSED: 0,
        STATE_GONE: 1,
        "not-evaluated": 0,
    }
    assert before["severity"] == {"high": 3, "medium": 2, "low": 2, "info": 0}
    assert sum(before["state"].values()) == sum(before["severity"].values()) == 7
    # only the matching entries: the canary on DEVICE and the policy finding on THIRD_DEVICE
    assert after["state"] == {
        STATE_NEW: 2,
        STATE_OPEN_KNOWN: 0,
        STATE_SUPPRESSED: 0,
        STATE_GONE: 0,
        "not-evaluated": 0,
    }
    assert after["severity"] == {"high": 2, "medium": 0, "low": 0, "info": 0}
    assert summary["total_matching"] == 2
    # a filter that matches nothing still says how much there was to choose from
    nothing = _summary(populated, severity="info")
    assert nothing["total_matching"] == 0
    assert nothing["items"] == ()
    assert nothing["counts_before_filter"] == before


def test_findings_summary_refuses_an_unknown_rule_id_like_other_invalid_input(populated):
    with pytest.raises(query.QueryError, match="the catalog holds no rule"):
        _summary(populated, rule_id="fortios.no.such.rule")
    with pytest.raises(query.QueryError, match="rule_id must be a non-empty string"):
        _summary(populated, rule_id="")
    with pytest.raises(query.QueryError, match="severity must be one of"):
        _summary(populated, severity="critical")
    with pytest.raises(query.QueryError, match="state must be one of"):
        _summary(populated, state="open")
    with pytest.raises(query.QueryError, match="now must be"):
        query.findings_summary(populated.store, TENANT, SUMMARY_RULES)
    # a rule of the catalog without any finding is a valid, empty filter
    assert _summary(populated, rule_id=RULE_WAN, state=STATE_NEW)["total_matching"] == 0


def test_findings_summary_honours_an_active_and_ignores_an_expired_suppression(populated):
    active = _summary(populated, suppressions=(suppression(populated.loose),), suppressions_configured=True)
    states = {item["fingerprint"]: item["state"] for item in active["items"]}
    assert states[populated.loose.fingerprint()] == STATE_SUPPRESSED
    assert active["counts_before_filter"]["state"][STATE_SUPPRESSED] == 1
    assert active["suppressions_configured"] is True
    only = _summary(populated, suppressions=(suppression(populated.loose),), state=STATE_SUPPRESSED)
    assert tuple(item["fingerprint"] for item in only["items"]) == (populated.loose.fingerprint(),)
    expired = _summary(
        populated,
        suppressions=(suppression(populated.loose, expires=NOW - timedelta(hours=1)),),
        suppressions_configured=True,
    )
    states = {item["fingerprint"]: item["state"] for item in expired["items"]}
    assert states[populated.loose.fingerprint()] == STATE_NEW
    assert expired["counts_before_filter"]["state"][STATE_SUPPRESSED] == 0
    assert expired["suppressions_configured"] is True
    foreign = _summary(populated, suppressions=(suppression(populated.loose, device=SECOND_DEVICE),))
    states = {item["fingerprint"]: item["state"] for item in foreign["items"]}
    assert states[populated.loose.fingerprint()] == STATE_NEW
    assert _summary(populated)["suppressions_configured"] is False


def test_findings_summary_carries_no_evidence_section_or_line(populated):
    summary = _summary(populated)
    assert set(summary) == set(query.SUMMARY_KEYS)
    assert summary["items"]
    for item in summary["items"]:
        assert set(item) == set(query.SUMMARY_ITEM_KEYS)
    keys = collected_keys(summary)
    for name in ("evidence", "section", "line", "rule_status", "rule_version", "class"):
        assert name not in keys
    assert not keys & FORBIDDEN_KEYS
    assert CANARY_EVIDENCE not in blob(summary)
    assert CANARY_SOURCE not in blob(summary)


def test_findings_summary_does_not_cross_tenants(populated):
    summary = _summary(populated, limit=200)
    assert OTHER_CANARY not in blob(summary)
    assert populated.stranger.fingerprint() not in {item["fingerprint"] for item in summary["items"]}
    foreign = query.findings_summary(populated.store, OTHER_TENANT, SUMMARY_RULES, now=NOW)
    assert tuple(item["fingerprint"] for item in foreign["items"]) == (populated.stranger.fingerprint(),)


def test_findings_summary_keeps_a_deterministic_order(populated):
    _third_device(populated)
    items = _summary(populated)["items"]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    keys = [(item["device"], order[item["severity"]], item["rule_id"], item["object_key"]) for item in items]
    assert keys == sorted(keys)
    assert items[0]["device"] == DEVICE
    assert items[0]["severity"] == "high"
    assert items[-1]["device"] == THIRD_DEVICE
    assert items == _summary(populated)["items"]


def test_findings_summary_reports_not_evaluated_like_list_findings(store):
    first, carried, plain, gone = _skipped_history(store)
    rules = (make_rule(RULE_DANGLING), make_rule("exos.port.optional"), make_rule(RULE_WAN, severity="medium"))
    summary = query.findings_summary(store, TENANT, rules, now=NOW)
    listing = query.list_findings(store, TENANT, DEVICE, now=NOW)
    states = {item["fingerprint"]: item["state"] for item in summary["items"]}
    assert states == {
        plain.fingerprint(): STATE_NEW,
        carried.fingerprint(): "not-evaluated",
        gone.fingerprint(): STATE_GONE,
    }
    assert summary["counts_before_filter"]["state"]["not-evaluated"] == 1
    only = query.findings_summary(store, TENANT, rules, now=NOW, state="not-evaluated")
    expected = query.list_findings(store, TENANT, DEVICE, now=NOW, state="not-evaluated")
    assert only["total_matching"] == expected["total"] == 1
    assert listing["total"] == summary["total_matching"]


def test_findings_summary_of_an_empty_store_is_empty(store):
    summary = query.findings_summary(store, TENANT, SUMMARY_RULES, now=NOW)
    assert summary["items"] == ()
    assert summary["total_matching"] == summary["returned"] == 0
    assert summary["truncated"] is False
    assert summary["counts_before_filter"] == summary["counts_after_filter"]
    unknown = query.findings_summary(store, TENANT, SUMMARY_RULES, device="fw-z.example.invalid", now=NOW)
    assert unknown["items"] == ()


def test_suppressions_configured_is_an_optional_key_of_status_and_listing(populated):
    plain_status = query.audit_status(populated.store, TENANT, now=NOW)
    plain_listing = query.list_findings(populated.store, TENANT, DEVICE, now=NOW)
    assert set(plain_status) == set(query.STATUS_KEYS)
    assert set(plain_listing) == set(query.LISTING_KEYS)
    for flag in (False, True):
        status = query.audit_status(populated.store, TENANT, now=NOW, suppressions_configured=flag)
        listing = query.list_findings(populated.store, TENANT, DEVICE, now=NOW, suppressions_configured=flag)
        never = query.list_findings(populated.store, TENANT, SECOND_DEVICE, now=NOW, suppressions_configured=flag)
        assert status.pop("suppressions_configured") is flag
        assert listing.pop("suppressions_configured") is flag
        assert never.pop("suppressions_configured") is flag
        assert status == plain_status
        assert listing == plain_listing
