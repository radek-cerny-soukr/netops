"""Review finding N1: a member row missing its Consistency value must not be filled from the Reason words.

DERIVED from the DOC example of tests/test_switch_vpc.py (Cisco TechNote 218333): only the member row is replaced
by ``20 Po20 down* Consistency Check Not Performed -`` - the supported multi-word Reason and ``-`` Active vlans
with the Consistency column (``success``) dropped. All other DOC data stays valid and must be kept.
"""
import hashlib

import test_switch_vpc as base

MISSING_CONSISTENCY = "20 Po20 down* Consistency Check Not Performed -"
DOC_SCALARS = {
    "domain_id": 1, "peer_status": "peer adjacency formed ok", "keepalive_status": "peer is alive",
    "role": "secondary", "consistency_status": "success", "consistency_reason": None, "configured_vpcs": 1,
}


def _missing_consistency_text():
    return base._replace(base.DOC, "20 Po20 up success success 1-2,10", MISSING_CONSISTENCY)


def _assert_members_missing_rest_kept(summary):
    # 99-N1: the row must not be taken as consistency="Consistency", reason="Check Not Performed".
    assert summary["state"] == "partial", summary
    assert summary["missing_fields"] == ["members"], summary
    assert summary["members"] == [], summary
    assert summary["peer_links"] == [base.DOC_PEER_LINK]
    assert {key: summary[key] for key in DOC_SCALARS} == DOC_SCALARS
    assert set(summary) == base.FIELDS


def test_missing_consistency_column_is_not_shifted_from_reason():
    _assert_members_missing_rest_kept(base._summarize(_missing_consistency_text()))


def test_explicit_consistency_kept_unknown_not_fully_recognized():
    failed = base._summarize(base._replace(base.DOC, "20 Po20 up success success 1-2,10",
                                           "20 Po20 down* failed Consistency Check Not Performed -"))
    assert failed["state"] == "measured" and failed["missing_fields"] == []
    assert failed["members"] == [{"id": 20, "port": "Po20", "status": "down*", "consistency": "failed",
                                  "reason": "Consistency Check Not Performed", "active_vlans": "-"}]
    unknown = base._summarize(base._replace(base.DOC, "20 Po20 up success success 1-2,10",
                                            "20 Po20 up bogus success 1-2,10"))
    assert unknown["state"] == "partial" and "members" in unknown["missing_fields"]
    assert unknown["peer_links"] == [base.DOC_PEER_LINK] and unknown["domain_id"] == 1


def test_public_ssh_read_missing_consistency_is_partial_and_keeps_body(tmp_path, monkeypatch):
    text = _missing_consistency_text()
    raw = text.encode("utf-8")
    expected_sha = hashlib.sha256(raw).hexdigest()
    contracts, gateway, calls = base._gateway(tmp_path, monkeypatch, {"show vpc brief": text})
    answer = base._ssh_read(contracts, gateway, 1, query="vpc_status", offset=0)
    assert answer["ok"] is True, answer
    _assert_members_missing_rest_kept(answer["vpc"])
    assert answer["complete"] is True and answer["pagination_source"] == "fresh"
    assert answer["untrusted_device_output"] == text and MISSING_CONSISTENCY in answer["untrusted_device_output"]
    assert answer["content_sha256"] == expected_sha and answer["total_bytes"] == len(raw)
    base._assert_body_untouched(answer, text)
    assert calls.count("show vpc brief") == 1
