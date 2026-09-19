from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile as temporary_directory

from netops_core.audit import AuditPersistenceError, Recorder
import netops_helper.audit as audit


def test_audit_rotates_and_enforces_total_budget(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper", 300, 3))

    for index in range(30):
        audit.record("test", device="device-a", status="ok", detail=f"event-{index:02d}")

    segments = sorted(tmp_path.glob("audit.jsonl*"))
    assert [item.name for item in segments] == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"]
    assert sum(item.stat().st_size for item in segments) <= 900
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in segments)
    for item in segments:
        assert all(json.loads(line)["event"] == "test" for line in item.read_text().splitlines())


def test_audit_keeps_read_metadata_and_refuses_phase2_fields(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(path, "helper"))
    audit.record(
        "ssh_read", device="device-a", status="ok", query="interface_details",
        total_bytes=1234, result_sha256="a" * 64,
    )
    payload = json.loads(path.read_text())
    assert payload["component"] == "helper"
    assert payload["device"] == "device-a"
    assert payload["query"] == "interface_details"
    assert payload["total_bytes"] == 1234
    for dead in ("target", "max_hops", "use_basic_auth", "change_id", "persistent"):
        try:
            audit.record("ssh_read", **{dead: "dead-field"})
        except ValueError:
            pass
        else:
            raise AssertionError(f"dead audit field was accepted: {dead}")
    assert len(path.read_text().splitlines()) == 1


def test_audit_rejects_record_larger_than_segment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path / "audit.jsonl", "helper", 64))
    try:
        audit.record("test", detail="x" * 200)
    except AuditPersistenceError as exc:
        assert "segment limit" in str(exc)
    else:
        raise AssertionError("oversized audit record was accepted")


def _assert_operation_id_contract(path: Path) -> None:
    previous = audit._RECORDER
    audit._RECORDER = Recorder(path, "helper")
    try:
        operation_id = "op_" + "a" * 32
        audit.record(
            "ssh_read", operation_id=operation_id,
            device="device-a", status="started",
        )
        payload = json.loads(path.read_text())
        assert payload["operation_id"] == operation_id

        invalid = (
            None,
            7,
            "",
            "a" * 32,
            "op_" + "A" * 32,
            "op_" + "a" * 31,
            "op_" + "a" * 33,
            "op_" + "../secret-input",
        )
        for value in invalid:
            try:
                audit.record("ssh_read", operation_id=value, status="started")
            except ValueError:
                pass
            else:
                raise AssertionError(f"invalid operation_id was accepted: {value!r}")
        assert len(path.read_text().splitlines()) == 1
    finally:
        audit._RECORDER = previous


def test_audit_operation_id_has_exact_allowlisted_format(tmp_path: Path) -> None:
    _assert_operation_id_contract(tmp_path / "operation-id.jsonl")


def main() -> int:
    with temporary_directory.TemporaryDirectory() as raw:
        _assert_operation_id_contract(Path(raw) / "operation-id.jsonl")
    print("audit_contract_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
