import json
from datetime import datetime, timedelta, timezone

import pytest

from netops_auditor.findings import Finding
from netops_auditor.suppressions import (
    Suppression,
    SuppressionError,
    active_fingerprints,
    declared_tenant,
    expired,
    fingerprint_of,
    load,
)

RULE_ID = "L1-001"
RULE_VERSION = 1
DEVICE = "fw-a.example.invalid"
OBJECT_KEY = "firewall policy/1"
REASON = "schvalena vyjimka, sprava jen z jump hostu 192.0.2.10"
AUTHOR = "radek"
CREATED = "2026-09-12T10:00:00Z"
EXPIRES = "2026-12-31T00:00:00Z"
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"

CREATED_AT = datetime(2026, 9, 12, 10, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2026, 12, 31, 0, 0, 0, tzinfo=timezone.utc)
BEFORE = EXPIRES_AT - timedelta(seconds=1)
AFTER = EXPIRES_AT + timedelta(seconds=1)

BAD_MOMENTS = (
    "2026-12-31T00:00:00+00:00",
    "2026-12-31 00:00:00Z",
    "2026-12-31T00:00:00.000Z",
    "2026-12-31T00:00:00",
    "2026-12-31T00:00:00z",
    "2026-12-31",
    "2026-9-30T00:00:00Z",
    "",
    "   ",
    None,
    20261231,
)


def entry(
    rule_id=RULE_ID,
    rule_version=RULE_VERSION,
    device=DEVICE,
    object_key=OBJECT_KEY,
    reason=REASON,
    author=AUTHOR,
    created=CREATED,
    expires=EXPIRES,
):
    return {
        "fingerprint": fingerprint_of(rule_id, rule_version, device, object_key),
        "rule_id": rule_id,
        "rule_version": rule_version,
        "device": device,
        "object_key": object_key,
        "reason": reason,
        "author": author,
        "created": created,
        "expires": expires,
    }


def write(tmp_path, items, version=1, extra=None, name="suppressions.json"):
    document = {"version": version, "suppressions": items}
    if extra is not None:
        document.update(extra)
    path = tmp_path / name
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return path


def write_raw(tmp_path, text, name="suppressions.json"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_file_loads_every_field(tmp_path):
    path = write(tmp_path, [entry()])
    loaded = load(path)
    assert len(loaded) == 1
    one = loaded[0]
    assert isinstance(one, Suppression)
    assert one.fingerprint == fingerprint_of(RULE_ID, RULE_VERSION, DEVICE, OBJECT_KEY)
    assert (one.rule_id, one.rule_version, one.device, one.object_key) == (RULE_ID, RULE_VERSION, DEVICE, OBJECT_KEY)
    assert (one.reason, one.author) == (REASON, AUTHOR)
    assert one.created == CREATED_AT
    assert one.expires == EXPIRES_AT
    assert load(str(path)) == loaded
    with pytest.raises(AttributeError):
        one.reason = "jiny duvod"


def test_empty_suppression_list_is_legitimate(tmp_path):
    loaded = load(write(tmp_path, []))
    assert loaded == ()
    assert active_fingerprints(loaded, BEFORE) == frozenset()
    assert expired(loaded, AFTER) == ()


def test_missing_file_is_an_error(tmp_path):
    with pytest.raises(SuppressionError, match="cannot read suppression file"):
        load(tmp_path / "neexistuje.json")
    with pytest.raises(SuppressionError, match="cannot read suppression file"):
        load(tmp_path)


def test_unknown_file_version_is_an_error(tmp_path):
    for version in (2, 0, "1", None, True):
        with pytest.raises(SuppressionError, match="unknown suppression file version"):
            load(write(tmp_path, [entry()], version=version))


def test_document_must_be_an_object_with_a_list_of_suppressions(tmp_path):
    with pytest.raises(SuppressionError, match="is not valid JSON"):
        load(write_raw(tmp_path, "{neni json"))
    with pytest.raises(SuppressionError, match="must hold an object"):
        load(write_raw(tmp_path, json.dumps([entry()])))
    with pytest.raises(SuppressionError, match="missing document fields: version"):
        load(write_raw(tmp_path, json.dumps({"suppressions": []})))
    with pytest.raises(SuppressionError, match="missing document fields: suppressions"):
        load(write_raw(tmp_path, json.dumps({"version": 1})))
    with pytest.raises(SuppressionError, match="suppressions must be a list"):
        load(write_raw(tmp_path, json.dumps({"version": 1, "suppressions": {}})))
    with pytest.raises(SuppressionError, match="suppression 0: must be an object"):
        load(write(tmp_path, ["L1-001"]))


def test_unknown_document_field_is_an_error(tmp_path):
    path = write(tmp_path, [entry()], extra={"default_expires": EXPIRES})
    with pytest.raises(SuppressionError, match="unknown document fields: default_expires"):
        load(path)


def test_an_unbound_file_still_works(tmp_path):
    path = write(tmp_path, [entry()])
    assert declared_tenant(path) is None
    assert len(load(path)) == 1
    assert len(load(path, TENANT_A)) == 1
    assert len(load(path, TENANT_B)) == 1


def test_a_bound_file_matching_the_tenant_works(tmp_path):
    path = write(tmp_path, [entry()], extra={"tenant": TENANT_A})
    assert declared_tenant(path) == TENANT_A
    loaded = load(path, TENANT_A)
    assert len(loaded) == 1
    assert loaded[0].fingerprint == fingerprint_of(RULE_ID, RULE_VERSION, DEVICE, OBJECT_KEY)
    assert len(load(path)) == 1


def test_a_file_bound_to_another_tenant_is_refused_naming_both_tenants(tmp_path):
    path = write(tmp_path, [entry()], extra={"tenant": TENANT_A})
    with pytest.raises(SuppressionError, match="%s.*%s" % (TENANT_A, TENANT_B)):
        load(path, TENANT_B)


def test_tenant_must_be_a_non_empty_string_when_present(tmp_path):
    for value in ("", "   ", 1, True, [], {}, None):
        with pytest.raises(SuppressionError, match="tenant must be a non-empty string"):
            load(write(tmp_path, [entry()], extra={"tenant": value}))


def test_unknown_item_field_is_an_error(tmp_path):
    extra = entry()
    extra["scope"] = "vsechna zarizeni"
    with pytest.raises(SuppressionError, match="unknown fields: scope"):
        load(write(tmp_path, [extra]))


def test_expiration_is_mandatory(tmp_path):
    without = entry()
    del without["expires"]
    with pytest.raises(SuppressionError, match="missing fields: expires"):
        load(write(tmp_path, [without]))
    for empty in ("", "   ", None):
        with pytest.raises(SuppressionError, match="expires must be ISO 8601 UTC"):
            load(write(tmp_path, [entry(expires=empty)]))
    assert load(write(tmp_path, [entry()]))[0].expires == EXPIRES_AT


def test_reason_and_author_are_mandatory(tmp_path):
    for name in ("reason", "author"):
        without = entry()
        del without[name]
        with pytest.raises(SuppressionError, match="missing fields: %s" % name):
            load(write(tmp_path, [without]))
        for empty in ("", "   ", "\t\n", None, 5):
            item = entry()
            item[name] = empty
            with pytest.raises(SuppressionError, match="%s must be a non-empty string" % name):
                load(write(tmp_path, [item]))
    loaded = load(write(tmp_path, [entry()]))[0]
    assert loaded.reason == REASON
    assert loaded.author == AUTHOR


def test_identity_fields_must_carry_text(tmp_path):
    for name in ("rule_id", "device", "object_key"):
        item = entry()
        item[name] = ""
        with pytest.raises(SuppressionError, match="%s must be a non-empty string" % name):
            load(write(tmp_path, [item]))


def test_reason_is_kept_verbatim(tmp_path):
    loaded = load(write(tmp_path, [entry(reason="  duvod s mezerami  ")]))
    assert loaded[0].reason == "  duvod s mezerami  "


def test_rule_version_must_be_an_integer(tmp_path):
    for value in ("1", 1.5, True, None):
        item = entry()
        item["rule_version"] = value
        with pytest.raises(SuppressionError, match="rule_version must be an integer"):
            load(write(tmp_path, [item]))
    assert load(write(tmp_path, [entry(rule_version=7)]))[0].rule_version == 7


def test_fingerprint_is_recomputed_from_components(tmp_path):
    loaded = load(write(tmp_path, [entry(rule_version=3, device="fw-b.example.invalid")]))
    assert loaded[0].fingerprint == fingerprint_of(RULE_ID, 3, "fw-b.example.invalid", OBJECT_KEY)


def test_fingerprint_mismatch_is_an_error(tmp_path):
    tampered = entry()
    tampered["device"] = "fw-b.example.invalid"
    with pytest.raises(SuppressionError, match="does not match components"):
        load(write(tmp_path, [tampered]))
    foreign = entry()
    foreign["fingerprint"] = fingerprint_of(RULE_ID, RULE_VERSION, DEVICE, "firewall policy/2")
    with pytest.raises(SuppressionError, match="does not match components"):
        load(write(tmp_path, [foreign]))
    for junk in ("", "neni hash", None, 123, fingerprint_of(RULE_ID, RULE_VERSION, DEVICE, OBJECT_KEY).upper()):
        item = entry()
        item["fingerprint"] = junk
        with pytest.raises(SuppressionError, match="does not match components"):
            load(write(tmp_path, [item]))


def test_fingerprint_matches_the_finding_implementation():
    finding = Finding(
        rule_id="L1-002",
        rule_version=3,
        device="fw-b.example.invalid",
        object_key="system interface/wan1",
        severity="high",
        rule_class="fakt",
        section="system interface",
        line=42,
        evidence=(("allowaccess", "http"),),
    )
    assert (
        fingerprint_of(finding.rule_id, finding.rule_version, finding.device, finding.object_key)
        == finding.fingerprint()
    )


def test_round_trip_from_a_real_finding(tmp_path):
    finding = Finding(
        rule_id="L1-003",
        rule_version=2,
        device="fw-c.example.invalid",
        object_key="firewall policy/9",
        severity="medium",
        rule_class="usudek",
        section="firewall policy",
        line=7,
        evidence=(("dstaddr", "198.51.100.0/24"),),
    )
    item = {
        "fingerprint": finding.fingerprint(),
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "device": finding.device,
        "object_key": finding.object_key,
        "reason": REASON,
        "author": AUTHOR,
        "created": CREATED,
        "expires": EXPIRES,
    }
    loaded = load(write(tmp_path, [item]))
    assert loaded[0].fingerprint == finding.fingerprint()
    assert finding.as_dict()["fingerprint"] in active_fingerprints(loaded, BEFORE)
    assert active_fingerprints(loaded, EXPIRES_AT) == frozenset()


def test_moments_must_be_iso_8601_utc_seconds(tmp_path):
    for value in BAD_MOMENTS:
        with pytest.raises(SuppressionError, match="expires must be ISO 8601 UTC"):
            load(write(tmp_path, [entry(expires=value)]))
        with pytest.raises(SuppressionError, match="created must be ISO 8601 UTC"):
            load(write(tmp_path, [entry(created=value)]))
    loaded = load(write(tmp_path, [entry(created="2026-01-02T03:04:05Z")]))
    assert loaded[0].created == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_created_must_be_before_expires(tmp_path):
    with pytest.raises(SuppressionError, match="is not before expires"):
        load(write(tmp_path, [entry(created=EXPIRES, expires=EXPIRES)]))
    with pytest.raises(SuppressionError, match="is not before expires"):
        load(write(tmp_path, [entry(created="2027-01-01T00:00:00Z", expires=EXPIRES)]))
    loaded = load(write(tmp_path, [entry(created="2026-12-30T23:59:59Z", expires=EXPIRES)]))
    assert loaded[0].created < loaded[0].expires


def test_duplicate_fingerprint_is_an_error(tmp_path):
    with pytest.raises(SuppressionError, match="duplicate fingerprint"):
        load(write(tmp_path, [entry(), entry(reason="jiny duvod", author="nekdo jiny")]))
    loaded = load(write(tmp_path, [entry(), entry(object_key="firewall policy/2")]))
    assert len({one.fingerprint for one in loaded}) == 2


def test_is_active_holds_until_the_expires_instant(tmp_path):
    one = load(write(tmp_path, [entry()]))[0]
    assert one.is_active(BEFORE) is True
    assert one.is_active(EXPIRES_AT) is False
    assert one.is_active(AFTER) is False


def test_active_and_expired_split_on_the_same_boundary(tmp_path):
    early = entry(object_key="firewall policy/2", expires="2026-09-30T00:00:00Z")
    loaded = load(write(tmp_path, [entry(), early]))
    both = frozenset(one.fingerprint for one in loaded)
    september = datetime(2026, 9, 20, 0, 0, 0, tzinfo=timezone.utc)
    october = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert active_fingerprints(loaded, september) == both
    assert expired(loaded, september) == ()
    assert active_fingerprints(loaded, october) == frozenset({loaded[0].fingerprint})
    assert expired(loaded, october) == (loaded[1],)
    assert active_fingerprints(loaded, EXPIRES_AT) == frozenset()
    assert expired(loaded, EXPIRES_AT) == (loaded[0], loaded[1])
    assert isinstance(active_fingerprints(loaded, september), frozenset)


def test_now_must_be_an_aware_datetime(tmp_path):
    loaded = load(write(tmp_path, [entry()]))
    naive = datetime(2026, 9, 20, 0, 0, 0)
    with pytest.raises(SuppressionError, match="timezone aware"):
        loaded[0].is_active(naive)
    with pytest.raises(SuppressionError, match="timezone aware"):
        active_fingerprints(loaded, naive)
    with pytest.raises(SuppressionError, match="timezone aware"):
        expired(loaded, naive)
    with pytest.raises(SuppressionError, match="must be a datetime"):
        loaded[0].is_active(EXPIRES)


def test_other_offsets_see_the_same_boundary(tmp_path):
    one = load(write(tmp_path, [entry()]))[0]
    local = timezone(timedelta(hours=2))
    assert one.is_active(BEFORE.astimezone(local)) is True
    assert one.is_active(EXPIRES_AT.astimezone(local)) is False
