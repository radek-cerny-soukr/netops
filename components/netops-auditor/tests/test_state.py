from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from netops_auditor.findings import Finding
from netops_auditor.state import (
    STATE_GONE,
    STATE_NEW,
    STATE_OPEN_KNOWN,
    STATE_SUPPRESSED,
    GoneFinding,
    classify,
)

TENANT = "tenant-a"
DEVICE = "fw-a.example.invalid"
NOW = datetime(2026, 9, 12, 6, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(days=30)
EARLIER = NOW - timedelta(days=1)
ABSENT = "0" * 64


@dataclass(frozen=True)
class FakeSuppression:
    fingerprint: str
    expires: datetime
    reason: str = "ticket NET-1"
    author: str = "radek"

    def is_active(self, now):
        return now < self.expires


def make_finding(rule_id="L1-001", object_key="firewall policy/1", severity="high", rule_version=1, tenant=TENANT):
    return Finding(
        rule_id=rule_id,
        rule_version=rule_version,
        tenant=tenant,
        device=DEVICE,
        object_key=object_key,
        severity=severity,
        rule_class="fakt",
        section="firewall policy",
        line=12,
        evidence=(("srcaddr", "192.0.2.0/24"),),
    )


def previous_entry(finding, severity=None):
    item = finding.as_dict()
    if severity is not None:
        item["severity"] = severity
    return item


def state_of(result, finding):
    return dict(result.states)[finding.fingerprint()]


def test_finding_without_baseline_or_suppression_is_new():
    finding = make_finding()
    result = classify((finding,), frozenset(), (), (), NOW)
    assert result.states == ((finding.fingerprint(), STATE_NEW),)
    assert result.counts == {STATE_NEW: 1, STATE_OPEN_KNOWN: 0, STATE_SUPPRESSED: 0, STATE_GONE: 0}


def test_finding_in_baseline_is_open_known_and_stays_visible():
    finding = make_finding()
    result = classify((finding,), frozenset({finding.fingerprint()}), (), (), NOW)
    assert result.states == ((finding.fingerprint(), STATE_OPEN_KNOWN),)
    assert result.counts[STATE_OPEN_KNOWN] == 1
    assert result.counts[STATE_NEW] == 0
    assert result.counts[STATE_SUPPRESSED] == 0


def test_open_known_is_not_suppression():
    known = make_finding(rule_id="L1-001", object_key="firewall policy/1")
    silenced = make_finding(rule_id="L1-002", object_key="firewall policy/2")
    suppressions = (FakeSuppression(fingerprint=silenced.fingerprint(), expires=LATER),)
    result = classify(
        (known, silenced),
        frozenset({known.fingerprint()}),
        suppressions,
        (),
        NOW,
    )
    assert state_of(result, known) == STATE_OPEN_KNOWN
    assert state_of(result, silenced) == STATE_SUPPRESSED
    assert result.counts[STATE_OPEN_KNOWN] == 1
    assert result.counts[STATE_SUPPRESSED] == 1
    assert len(result.states) == 2


def test_active_suppression_wins_over_baseline():
    finding = make_finding()
    suppressions = (FakeSuppression(fingerprint=finding.fingerprint(), expires=LATER),)
    result = classify((finding,), frozenset({finding.fingerprint()}), suppressions, (), NOW)
    assert result.states == ((finding.fingerprint(), STATE_SUPPRESSED),)
    assert result.counts == {STATE_NEW: 0, STATE_OPEN_KNOWN: 0, STATE_SUPPRESSED: 1, STATE_GONE: 0}
    assert result.expired_suppressions == ()
    assert result.orphaned_suppressions == ()


def test_gone_carries_original_severity_for_high_and_low():
    high = make_finding(rule_id="L1-001", object_key="firewall policy/1", severity="high")
    low = make_finding(rule_id="L1-009", object_key="system global/timeout", severity="low")
    previous = (previous_entry(high), previous_entry(low))
    result = classify((), frozenset(), (), previous, NOW)
    assert result.gone == (
        GoneFinding(high.fingerprint(), "L1-001", "firewall policy/1", "high"),
        GoneFinding(low.fingerprint(), "L1-009", "system global/timeout", "low"),
    )
    assert result.counts[STATE_GONE] == 2


def test_gone_is_ordered_by_rule_id_and_object_key():
    first = make_finding(rule_id="L1-001", object_key="firewall policy/1")
    second = make_finding(rule_id="L1-001", object_key="firewall policy/2")
    third = make_finding(rule_id="L1-002", object_key="firewall policy/1")
    previous = (previous_entry(third), previous_entry(second), previous_entry(first))
    result = classify((), frozenset(), (), previous, NOW)
    assert tuple((item.rule_id, item.object_key) for item in result.gone) == (
        ("L1-001", "firewall policy/1"),
        ("L1-001", "firewall policy/2"),
        ("L1-002", "firewall policy/1"),
    )


def test_finding_still_reported_today_is_not_gone():
    finding = make_finding()
    result = classify((finding,), frozenset(), (), (previous_entry(finding),), NOW)
    assert result.gone == ()
    assert result.counts[STATE_GONE] == 0
    assert state_of(result, finding) == STATE_NEW


def test_gone_ignores_baseline_and_suppression():
    finding = make_finding()
    suppressions = (FakeSuppression(fingerprint=finding.fingerprint(), expires=LATER),)
    result = classify(
        (),
        frozenset({finding.fingerprint()}),
        suppressions,
        (previous_entry(finding),),
        NOW,
    )
    assert result.counts[STATE_GONE] == 1
    assert result.gone[0].fingerprint == finding.fingerprint()


def test_expired_suppression_does_not_suppress_and_is_reported():
    finding = make_finding()
    suppression = FakeSuppression(fingerprint=finding.fingerprint(), expires=EARLIER)
    result = classify((finding,), frozenset(), (suppression,), (), NOW)
    assert result.states == ((finding.fingerprint(), STATE_NEW),)
    assert result.counts[STATE_SUPPRESSED] == 0
    assert result.expired_suppressions == (suppression,)


def test_expired_suppression_over_baseline_falls_back_to_open_known():
    finding = make_finding()
    suppression = FakeSuppression(fingerprint=finding.fingerprint(), expires=EARLIER)
    result = classify((finding,), frozenset({finding.fingerprint()}), (suppression,), (), NOW)
    assert result.states == ((finding.fingerprint(), STATE_OPEN_KNOWN),)
    assert result.counts[STATE_OPEN_KNOWN] == 1
    assert result.expired_suppressions == (suppression,)


def test_orphaned_suppression_is_reported():
    finding = make_finding()
    orphan = FakeSuppression(fingerprint=ABSENT, expires=LATER)
    result = classify((finding,), frozenset(), (orphan,), (), NOW)
    assert result.orphaned_suppressions == (orphan,)
    assert result.expired_suppressions == ()
    assert result.states == ((finding.fingerprint(), STATE_NEW),)


def test_suppression_matching_today_is_not_orphaned():
    finding = make_finding()
    suppression = FakeSuppression(fingerprint=finding.fingerprint(), expires=EARLIER)
    result = classify((finding,), frozenset(), (suppression,), (), NOW)
    assert result.orphaned_suppressions == ()
    assert result.expired_suppressions == (suppression,)


def test_suppression_for_gone_finding_is_orphaned():
    finding = make_finding()
    suppression = FakeSuppression(fingerprint=finding.fingerprint(), expires=LATER)
    result = classify((), frozenset(), (suppression,), (previous_entry(finding),), NOW)
    assert result.orphaned_suppressions == (suppression,)
    assert result.counts[STATE_GONE] == 1


def test_expired_and_orphaned_suppression_is_in_both_lists():
    dead = FakeSuppression(fingerprint=ABSENT, expires=EARLIER)
    result = classify((), frozenset(), (dead,), (), NOW)
    assert result.orphaned_suppressions == (dead,)
    assert result.expired_suppressions == (dead,)


def test_rule_version_change_orphans_the_old_suppression():
    old = make_finding(rule_version=1)
    new = make_finding(rule_version=2)
    suppression = FakeSuppression(fingerprint=old.fingerprint(), expires=LATER)
    result = classify((new,), frozenset(), (suppression,), (), NOW)
    assert old.fingerprint() != new.fingerprint()
    assert result.orphaned_suppressions == (suppression,)
    assert result.states == ((new.fingerprint(), STATE_NEW),)


def test_states_are_ordered_by_fingerprint():
    findings = tuple(make_finding(object_key="firewall policy/%d" % index) for index in range(1, 6))
    result = classify(findings, frozenset(), (), (), NOW)
    fingerprints = tuple(fingerprint for fingerprint, _ in result.states)
    assert fingerprints == tuple(sorted(finding.fingerprint() for finding in findings))


def test_counts_cover_all_four_states_at_once():
    fresh = make_finding(rule_id="L1-001", object_key="firewall policy/1")
    known = make_finding(rule_id="L1-002", object_key="firewall policy/2")
    silenced = make_finding(rule_id="L1-003", object_key="firewall policy/3")
    vanished = make_finding(rule_id="L1-004", object_key="firewall policy/4", severity="medium")
    suppressions = (FakeSuppression(fingerprint=silenced.fingerprint(), expires=LATER),)
    result = classify(
        (fresh, known, silenced),
        frozenset({known.fingerprint()}),
        suppressions,
        (previous_entry(vanished),),
        NOW,
    )
    assert result.counts == {STATE_NEW: 1, STATE_OPEN_KNOWN: 1, STATE_SUPPRESSED: 1, STATE_GONE: 1}
    assert tuple(result.counts) == (STATE_NEW, STATE_OPEN_KNOWN, STATE_SUPPRESSED, STATE_GONE)


def test_same_input_in_any_order_gives_identical_result():
    fresh = make_finding(rule_id="L1-001", object_key="firewall policy/1")
    known = make_finding(rule_id="L1-002", object_key="firewall policy/2")
    silenced = make_finding(rule_id="L1-003", object_key="firewall policy/3")
    gone_high = make_finding(rule_id="L1-004", object_key="firewall policy/4", severity="high")
    gone_low = make_finding(rule_id="L1-005", object_key="firewall policy/5", severity="low")
    live = FakeSuppression(fingerprint=silenced.fingerprint(), expires=LATER)
    dead = FakeSuppression(fingerprint=ABSENT, expires=EARLIER)
    baseline = frozenset({known.fingerprint()})
    first = classify(
        (fresh, known, silenced),
        baseline,
        (live, dead),
        (previous_entry(gone_high), previous_entry(gone_low)),
        NOW,
    )
    second = classify(
        (silenced, known, fresh),
        baseline,
        (dead, live),
        (previous_entry(gone_low), previous_entry(gone_high)),
        NOW,
    )
    assert first == second
    assert repr(first).encode("utf-8") == repr(second).encode("utf-8")


def test_duplicate_fingerprints_are_counted_once():
    finding = make_finding()
    twin = make_finding()
    result = classify((finding, twin), frozenset(), (), (previous_entry(finding), previous_entry(twin)), NOW)
    assert result.states == ((finding.fingerprint(), STATE_NEW),)
    assert result.counts[STATE_NEW] == 1


def test_empty_inputs_give_zero_counts():
    result = classify((), frozenset(), (), (), NOW)
    assert result.states == ()
    assert result.gone == ()
    assert result.orphaned_suppressions == ()
    assert result.expired_suppressions == ()
    assert result.counts == {STATE_NEW: 0, STATE_OPEN_KNOWN: 0, STATE_SUPPRESSED: 0, STATE_GONE: 0}


def test_reciprocal_unevaluated_absence_keeps_suppression_until_complete():
    old = make_finding()
    waiver = FakeSuppression(fingerprint=old.fingerprint(), expires=LATER)
    previous = (previous_entry(old),)
    partial = classify((make_finding(rule_id="fortios.snapshot.incomplete"),), (), (waiver,), previous, NOW)
    assert not partial.gone and not partial.orphaned_suppressions
    assert {item.fingerprint for item in partial.not_evaluated} == {old.fingerprint()}
    complete = classify((), (), (waiver,), previous, NOW)
    assert {item.fingerprint for item in complete.gone} == {old.fingerprint()}
    assert complete.orphaned_suppressions == (waiver,)
