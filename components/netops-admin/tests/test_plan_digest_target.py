"""1.0.10 B4c: plan_sha256 binds a profile plan to its target (device alias, platform, firmware)."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from conftest import request_bytes
from fake_fortios import FakeFortiOS

from netops_admin import engine, execute
from netops_admin.config import DEFAULT_LIMITS, Config, Device
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOT = (FIXTURES / "fortios_8_0_0.conf").read_bytes()
OTHER_FIRMWARE = SNAPSHOT.replace(b"8.0.0-FW-build0167", b"8.0.2-FW-build0251")


def body(**fields):
    fields.setdefault("op", "update")
    fields.setdefault("key", "spare-host")
    fields.setdefault("changes", {"comment": "approved"})
    return parse_request(request_bytes(**fields))


def two_devices(tmp_path, fake):
    def device(name):
        return Device(name=name, platform="fortios", address="192.0.2.1", port=22,
                      host_key_fingerprint="SHA256:" + "A" * 43, vault="/nonexistent/vault.json", credential="rw",
                      check_credential="ro", firmware=None, safeguard_seconds=180, confirm_margin_seconds=45,
                      protected={})
    config = Config(state_dir=str(tmp_path / "state"), audit_file=str(tmp_path / "audit" / "audit.jsonl"),
                    export_status_file=None, notify=None, limits=dict(DEFAULT_LIMITS),
                    devices={"fw-a": device("fw-a"), "fw-b": device("fw-b")})
    from enrollment_helpers import certify
    runtime = execute.Runtime(config, lambda _device: fake, sleep=fake.advance)
    return certify(certify(runtime, fake, "fw-a"), fake, "fw-b")


def test_the_same_request_on_two_devices_has_two_hashes():
    first = engine.build_plan("fortios", SNAPSHOT, body(), device="fw-a")
    second = engine.build_plan("fortios", SNAPSHOT, body(), device="fw-b")
    assert first["commands"] == second["commands"] and first["predicted"] == second["predicted"]
    assert first["device"] == "fw-a" and second["device"] == "fw-b"
    assert first["plan_sha256"] != second["plan_sha256"]


def test_another_firmware_has_another_hash():
    first = engine.build_plan("fortios", SNAPSHOT, body(), device="fw-a")
    second = engine.build_plan("fortios", OTHER_FIRMWARE, body(), device="fw-a")
    assert first["firmware"] != second["firmware"]
    assert first["commands"] == second["commands"] and first["predicted"] == second["predicted"]
    assert first["plan_sha256"] != second["plan_sha256"]


def test_the_same_target_has_the_same_hash():
    first = engine.build_plan("fortios", SNAPSHOT, body(request_id="req-b4c-0001"), device="fw-a")
    second = engine.build_plan("fortios", SNAPSHOT, body(request_id="req-b4c-0002"), device="fw-a")
    assert first["plan_sha256"] == second["plan_sha256"] == engine.plan_digest(first)


def test_the_alias_of_the_request_is_used_without_a_configured_device():
    named = engine.build_plan("fortios", SNAPSHOT, body(device="fw-a"))
    assert named["device"] == "fw-a"
    assert named["plan_sha256"] == engine.build_plan("fortios", SNAPSHOT, body(), device="fw-a")["plan_sha256"]


@pytest.mark.parametrize("field, value", [("device", "fw-b"), ("firmware", "8.0.1 build0245"), ("platform", "exos")])
def test_a_changed_target_breaks_the_plan_hash(field, value):
    document = engine.build_plan("fortios", SNAPSHOT, body(), device="fw-a")
    document[field] = value
    with pytest.raises(Rejected) as caught:
        engine.verify(document, SNAPSHOT)
    assert "plan_sha256" in caught.value.reasons[0]


def test_preview_hashes_differ_between_devices_and_apply_with_the_other_hash_is_refused(tmp_path):
    fake = FakeFortiOS()
    runtime = two_devices(tmp_path, fake)
    approved = body(request_id="req-b4c-0010")
    on_a = execute.preview(runtime, "fw-a", approved)
    on_b = execute.preview(runtime, "fw-b", approved)
    assert on_a["result"] == on_b["result"] == "ready"
    assert on_a["plan_sha256"] != on_b["plan_sha256"]
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "fw-a", approved, expected_plan_sha256=on_b["plan_sha256"])
    assert caught.value.reason_codes == ["plan_changed"]
    assert caught.value.reasons == [execute.PLAN_CHANGED]
    assert "another device or firmware" in execute.PLAN_CHANGED and "new preview" in execute.PLAN_CHANGED
    assert caught.value.reason_details[0]["actual"] == on_a["plan_sha256"]
    assert fake.applied_blocks == [] and fake.addresses["spare-host"].get("comment") != "approved"
    assert list(runtime.store.records()) == []
    record = execute.apply(runtime, "fw-a", approved, expected_plan_sha256=on_a["plan_sha256"])
    assert record["result"] == "confirmed" and record["plan"]["plan_sha256"] == on_a["plan_sha256"]
    assert record["plan"]["device"] == "fw-a"


def legacy(document, version):
    document["admin_version"] = version
    document["plan_sha256"] = engine._digest({"commands": document["commands"], "inverse": document["inverse"],
                                              "before": document["predicted"]["before"],
                                              "after": document["predicted"]["after"]})
    return document


def test_a_stored_plan_of_an_earlier_version_stays_readable(monkeypatch):
    monkeypatch.setattr(engine, "__version__", "1.0.10")
    document = legacy(engine.build_plan("fortios", SNAPSHOT, body(), device="fw-a"), "1.0.9")
    assert engine.verify(document, SNAPSHOT, expect="before")["result"] == "match"
    document["commands"] = document["commands"] + ["execute reboot"]
    with pytest.raises(Rejected):
        engine.verify(document, SNAPSHOT, expect="before")


@pytest.mark.parametrize("version", ["0.2.12", "1.0.10", "1.1.0", "dev"])
def test_the_content_only_hash_is_refused_from_this_version_on(monkeypatch, version):
    monkeypatch.setattr(engine, "__version__", "1.0.10")
    document = legacy(engine.build_plan("fortios", SNAPSHOT, body(), device="fw-a"), version)
    with pytest.raises(Rejected) as caught:
        engine.verify(document, SNAPSHOT, expect="before")
    assert "plan_sha256" in caught.value.reasons[0]


def test_the_content_only_hash_is_refused_for_the_running_version():
    document = engine.build_plan("fortios", SNAPSHOT, body(), device="fw-a")
    legacy(document, document["admin_version"])
    with pytest.raises(Rejected):
        engine.verify(document, SNAPSHOT, expect="before")


def test_the_plan_hash_ignores_the_reason_and_the_user_request():
    document = engine.build_plan("fortios", SNAPSHOT, body(), device="fw-a")
    changed = dataclasses.replace(body(), reason="another reason", user_request="another request")
    assert engine.build_plan("fortios", SNAPSHOT, changed, device="fw-a")["plan_sha256"] == document["plan_sha256"]
