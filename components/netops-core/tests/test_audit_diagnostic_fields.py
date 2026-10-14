import json

import pytest

from netops_core.audit import AuditFieldError, Recorder


def test_diagnostic_recipe_and_timeout_are_allowed_metadata(tmp_path):
    path = tmp_path / "audit.jsonl"
    recorder = Recorder(path, "helper")
    recorder.record("diagnostic", recipe="sessions", timeout=5)
    record = json.loads(path.read_text())
    assert record["recipe"] == "sessions"
    assert record["timeout"] == 5


def test_unknown_diagnostic_field_is_rejected_before_writing(tmp_path):
    path = tmp_path / "audit.jsonl"
    recorder = Recorder(path, "helper")
    with pytest.raises(AuditFieldError, match="unknown_diagnostic"):
        recorder.record("diagnostic", recipe="sessions", timeout=5, unknown_diagnostic=True)
    assert not path.exists()
